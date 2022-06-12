def required_scopes(required_scopes):
    def decorator(func):
        func.required_scopes = required_scopes
        return func

    return decorator
