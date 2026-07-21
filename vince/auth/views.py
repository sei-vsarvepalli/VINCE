#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# DM21-1126
########################################################################
"""
Lightweight debug/development endpoint for local auth mode.

The ``whoami`` view is only active when ``settings.DEBUG`` is ``True``.
It is intended **solely** for local development and automated testing and
must never be relied upon in production.

In ``AUTH_BACKEND_MODE=local`` the view also accepts the optional dev
bootstrap headers ``X-Dev-User``, ``X-Dev-Email``, and ``X-Dev-Groups``
to create/sync a local user on-the-fly (``DEBUG=True`` guard is enforced
inside the adapter).
"""

from django.conf import settings
from django.http import JsonResponse

from vince.auth.service import authenticate_request


def whoami(request):
    """
    Return JSON describing the currently authenticated user.

    Responds with HTTP 403 when ``settings.DEBUG`` is ``False`` so the
    endpoint cannot leak user information in production even if the URL
    is accidentally reachable.
    """
    if not getattr(settings, "DEBUG", False):
        return JsonResponse({"error": "Not available outside DEBUG mode."}, status=403)

    # In local mode, attempt header-based dev bootstrap if not already authed.
    user = request.user
    if not getattr(user, "is_authenticated", False):
        bootstrapped = authenticate_request(request)
        if bootstrapped is not None:
            user = bootstrapped

    if not getattr(user, "is_authenticated", False):
        return JsonResponse({"error": "Authentication required."}, status=401)

    return JsonResponse(
        {
            "username": user.username,
            "email": user.email,
            "groups": sorted(user.groups.values_list("name", flat=True)),
        }
    )
