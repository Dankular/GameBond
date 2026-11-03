"""Cached read-only Windows GPU performance counters, sampled off the UI thread."""
import json
import os
import subprocess
import threading
import time

GPU_SCRIPT = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$issues=@();$usage=$null;$memory=$null;$count=0
try {
 $samples=@((Get-Counter '\GPU Engine(*)\Utilization Percentage' -MaxSamples 1 -ErrorAction Stop).CounterSamples |
  Where-Object {$_.Status -eq 0} | Select-Object -First 8192)
 $engines=@($samples | Group-Object {$_.InstanceName -replace '^pid_\d+_',''} |
  ForEach-Object {($_.Group | Measure-Object CookedValue -Sum).Sum})
 if($engines.Count){$usage=[math]::Min(100,[math]::Max(0,($engines | Measure-Object -Maximum).Maximum));$count=$engines.Count}
} catch {$issues+= $_.Exception.Message}
try {
 $samples=@((Get-Counter '\GPU Adapter Memory(*)\Dedicated Usage' -MaxSamples 1 -ErrorAction Stop).CounterSamples |
  Where-Object {$_.Status -eq 0 -and $_.InstanceName -ne '_total'} | Select-Object -First 64)
 if($samples.Count){$memory=[long]($samples | Measure-Object CookedValue -Sum).Sum}
} catch {$issues+=$_.Exception.Message}
ConvertTo-Json -InputObject ([pscustomobject]@{percent=$usage;dedicated_used_bytes=$memory;engine_count=$count;errors=$issues}) -Depth 4 -Compress
'''


class WindowsGPUSampler:
    def __init__(self, *, interval=5, runner=None, clock=time.monotonic):
        self.interval, self.runner, self.clock = interval, runner, clock
        self.lock = threading.Lock(); self.last_started = None; self.busy = False
        self.closed = threading.Event()
        self.process=None
        self.latest = dict(percent=None, dedicated_used_bytes=None, dedicated_total_bytes=None,
                          available=False, status='not_sampled', errors=[])

    def sample(self):
        if os.name != 'nt':
            return {**self.latest, 'status':'unsupported_platform'}
        now = self.clock()
        with self.lock:
            if not self.busy and not self.closed.is_set() and (self.last_started is None or now-self.last_started>=self.interval):
                self.busy = True; self.last_started = now
                threading.Thread(target=self._collect, name='gamebond-gpu-counters', daemon=True).start()
            result = dict(self.latest)
            result['errors'] = list(result['errors'])
            result['sampling'] = self.busy
            if result.get('observed_monotonic') is not None and now-result['observed_monotonic']>max(15,self.interval*3):
                result.update(percent=None,dedicated_used_bytes=None,available=False,status='stale')
            return result

    def _collect(self):
        try:
            command=['powershell','-NoProfile','-NonInteractive','-Command',GPU_SCRIPT]
            if self.runner:
                completed=self.runner(command,capture_output=True,timeout=12,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                code,output=completed.returncode,completed.stdout
            else:
                process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                with self.lock:
                    self.process=process
                    if self.closed.is_set():process.terminate()
                try:
                    output,_=process.communicate(timeout=12);code=process.returncode
                except subprocess.TimeoutExpired:
                    process.terminate();process.communicate(timeout=3);raise RuntimeError('Windows GPU counter query timed out')
                finally:
                    with self.lock:
                        if self.process is process:self.process=None
            if code:raise RuntimeError('Windows GPU counters are unavailable')
            record = json.loads(output.decode('utf-8-sig'))
            percent, memory = record.get('percent'), record.get('dedicated_used_bytes')
            if percent is not None and (type(percent) not in (int,float) or not 0<=percent<=100):
                raise ValueError('Invalid GPU utilization counter')
            if memory is not None and (type(memory) is not int or memory<0):raise ValueError('Invalid GPU memory counter')
            available = percent is not None or memory is not None
            result = dict(percent=percent,dedicated_used_bytes=memory,dedicated_total_bytes=None,
                engine_count=record.get('engine_count',0),available=available,status='available' if available else 'unavailable',
                metric='busiest_engine_percent',errors=list(record.get('errors') or []),observed_at=time.time(),
                observed_monotonic=self.clock(),limitations=['GPU usage is the busiest engine across adapters.',
                    'Dedicated memory is usage, not adapter capacity. Counter names are English and can be unavailable on localized systems.'])
        except Exception as exc:
            result = dict(percent=None,dedicated_used_bytes=None,dedicated_total_bytes=None,available=False,
                          status='unavailable',errors=[str(exc)],observed_monotonic=self.clock())
        with self.lock:
            self.latest=result;self.busy=False

    def shutdown(self):
        self.closed.set()
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
