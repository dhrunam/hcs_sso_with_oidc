# apps/api/error_handlers.py
"""
Custom error handlers for API responses.
"""

import logging
from django.http import HttpResponseBadRequest, JsonResponse
from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """Custom exception handler for DRF"""
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    if response is not None:
        # Add custom error code
        response.data['status_code'] = response.status_code
        
        # Log errors (but not validation errors)
        if response.status_code >= 500:
            logger.error(f"Server error: {exc}", exc_info=True)
        elif response.status_code >= 400 and response.status_code != 400:
            logger.warning(f"Client error: {exc}")
    
    return response

def bad_request_handler(request, exception, template_name='400.html'):
    """400 error handler"""
    logger.warning(f"Bad request: {exception}")
    
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Bad Request',
            'status_code': 400,
            'message': str(exception) or 'Invalid request'
        }, status=400)
    
    from django.template import loader
    template = loader.get_template(template_name)
    return HttpResponseBadRequest(template.render())

def permission_denied_handler(request, exception, template_name='403.html'):
    """403 error handler"""
    logger.warning(f"Permission denied: {exception}")
    
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Forbidden',
            'status_code': 403,
            'message': 'You do not have permission to perform this action'
        }, status=403)
    
    from django.template import loader
    template = loader.get_template(template_name)
    return HttpResponseForbidden(template.render())

def page_not_found_handler(request, exception, template_name='404.html'):
    """404 error handler"""
    logger.warning(f"Page not found: {request.path}")
    
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Not Found',
            'status_code': 404,
            'message': 'The requested resource was not found'
        }, status=404)
    
    from django.template import loader
    template = loader.get_template(template_name)
    return HttpResponseNotFound(template.render())

def server_error_handler(request, template_name='500.html'):
    """500 error handler"""
    logger.error("Server error occurred", exc_info=True)
    
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Internal Server Error',
            'status_code': 500,
            'message': 'An internal server error occurred'
        }, status=500)
    
    from django.template import loader
    template = loader.get_template(template_name)
    return HttpResponseServerError(template.render())