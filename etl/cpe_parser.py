"""Parse CPE 2.3 formatted strings while retaining escaped components."""




def split_cpe(value):
    if not isinstance(value, str) or not value.startswith("cpe:2.3:"):
        raise ValueError("Expected CPE 2.3 formatted string")
    parts = []
    component = []
    escaped = False
    for char in value[len("cpe:2.3:"):]:
        if escaped:
            component.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(component))
            component.clear()
        else:
            component.append(char)
    parts.append("".join(component))
    if escaped or len(parts) != 11 or not all(parts):
        raise ValueError("Malformed CPE 2.3 components")
    if parts[0] not in {"a", "h", "o", "*", "-"}:
        raise ValueError("Invalid CPE part")
    return tuple(parts)


def has_wildcard(component):
    escaped = False
    for char in component:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char in "*?":
            return True
    return False


def product_key(parts):
    part, vendor, product = parts[:3]
    if part not in {"a", "h", "o"} or any(
        value == "-" or has_wildcard(value) for value in (vendor, product)
    ):
        return None, None, None
    return part, vendor.lower(), product.lower()
