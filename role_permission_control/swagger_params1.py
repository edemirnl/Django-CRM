from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter
from role_permission_control.models import Role

organization_params_in_header = OpenApiParameter(
    "org", OpenApiTypes.STR, OpenApiParameter.HEADER
)

organization_params = [
    organization_params_in_header,
]



