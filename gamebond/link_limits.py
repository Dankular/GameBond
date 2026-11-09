"""Shared limits for selectable physical uplinks and the GB03 path table."""
MIN_LINKS = 1
MAX_LINKS = 8


def stable_adapter_ids(values,count):
    return (isinstance(values,list) and len(values)==count and
            all(isinstance(v,str) and len(v)==38 and v.startswith('{') and v.endswith('}') for v in values)
            and len({v.casefold() for v in values})==count)


def valid_interface_indices(values,count):
    return (isinstance(values,list) and len(values)==count and
            all(type(v) is int and 0<v<(1<<24) for v in values) and len(set(values))==count)
