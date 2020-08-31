from django import template
from users.models import Profile

register = template.Library()

@register.simple_tag
def get_profile_image(user):
    p = Profile.objects.get(user=user)
    return p.image

