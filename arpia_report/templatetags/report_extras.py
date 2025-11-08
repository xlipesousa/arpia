import html

from django import template
from django.utils.safestring import mark_safe

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


@register.filter(name="preformatted")
def preformatted(value):
    """Escape text for <pre> blocks keeping quotes legible."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return mark_safe(html.escape(value, quote=False))
