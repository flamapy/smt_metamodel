from z3 import ModelRef, RatNumRef, IntNumRef


def config_sanitizer(config: ModelRef) -> dict[str, float | int]:
    sanitize_config: dict[str, float | int] = {}
    for var in config:
        value: float | int = 0
        if '/0' in str(var):
            continue
        if isinstance(config[var], RatNumRef):
            value = round(config[var].numerator_as_long() / config[var].denominator_as_long(), 2)
        elif isinstance(config[var], IntNumRef):
            value = config[var].as_long()
            if value == -1:
                continue
        sanitize_config[str(var)] = value
    return sanitize_config