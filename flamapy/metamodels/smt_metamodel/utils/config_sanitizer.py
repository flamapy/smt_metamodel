from z3 import ModelRef, RatNumRef, IntNumRef


def config_sanitizer(config: ModelRef) -> dict[str, float | int]:
    sanitize_config: dict[str, float | int] = {}
    for var in config:
        value = 0
        if '/0' in str(var):
            continue
        if isinstance(config[var], RatNumRef):
            value = config[var].numerator_as_long() / config[var].denominator_as_long()
        elif isinstance(config[var], IntNumRef):
            value = config[var].as_long()
        sanitize_config[str(var)] = value
    return sanitize_config