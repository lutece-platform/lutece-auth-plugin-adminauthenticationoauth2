/*
 * Copyright (c) 2002-2023, City of Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.adminauthenticationoauth2.web;

import fr.paris.lutece.plugins.adminauthenticationoauth2.service.session.Oauth2AdminUserSessionService;
import fr.paris.lutece.plugins.adminauthenticationoauth2.service.Oauth2Utils;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.security.AccessLogService;
import fr.paris.lutece.portal.service.security.AccessLoggerConstants;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class Oauth2AuthenticationJspBean implements Serializable
{

    /**
     * Process the logout of user
     *
     * @param request
     *            Http request
     * @return The Jsp URL of the process result
     */
    public String doLogout( HttpServletRequest request )
    {
        // Invalidation of the session
        HttpSession session = request.getSession( );

        AdminUser user = AdminAuthenticationService.getInstance( ).getRegisteredUser( request );

        if ( session != null )
        {
            Oauth2AdminUserSessionService.getInstance( ).removeAdminUserSession( session.getId( ) );
            AdminAuthenticationService.getInstance( ).unregisterUser( request );
        }

        StringBuilder strLogoutUrl = new StringBuilder( AdminAuthenticationService.getInstance( ).getDoLogoutUrl( ) );

        try
        {
            strLogoutUrl.append( "?redirect_uri=" )
                    .append( URLEncoder.encode( AppPathService.getAbsoluteUrl( request, AppPathService.getAdminMenuUrl( ) ), "UTF-8" ) );
        }
        catch( UnsupportedEncodingException e )
        {
            AppLogService.error( e );
        }

        AccessLogService.getInstance( ).info( AccessLoggerConstants.EVENT_TYPE_CONNECT, Oauth2Utils.CONSTANT_ACTION_DOLOGOUT, user, null,
                Oauth2Utils.CONSTANT_BO );

        return strLogoutUrl.toString( );
    }

}
