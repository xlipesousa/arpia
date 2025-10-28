from django import template

register = template.Library()


@register.filter(name="underscore_to_space")
def underscore_to_space(value):
    """Convert underscores to spaces in string-ish values.

    Non-string values are returned untouched so they continue to render
    naturally in the template.
    """
    if not isinstance(value, str):
        return value
    return value.replace("_", " ")
