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
/*
* Copyright (c) 2002-2013, Mairie de Paris
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
package fr.paris.lutece.plugins.adminauthenticationoauth2.business.authentication;

import fr.paris.lutece.plugins.adminauthenticationoauth2.service.Oauth2Service;
import fr.paris.lutece.plugins.adminauthenticationoauth2.service.Oauth2Utils;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.plugins.oauth2.service.DataClientService;
import fr.paris.lutece.plugins.oauth2.service.TokenService;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.authentication.AdminAuthentication;
import fr.paris.lutece.portal.service.admin.AccessDeniedException;
import fr.paris.lutece.portal.service.admin.AdminUserService;
import fr.paris.lutece.portal.service.security.UserNotSignedException;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * Data authentication module for admin authentication
 */
public class AdminOauth2Authentication implements AdminAuthentication
{

    /**
     *
     */
    public AdminOauth2Authentication( )
    {
        super( );
    }

    @Override
    public String getAuthServiceName( )
    {
        return AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_AUTH_SERVICE_NAME );
    }

    @Override
    public String getAuthType( HttpServletRequest request )
    {
        return HttpServletRequest.BASIC_AUTH;
    }

    @Override
    public AdminUser login( String strAccessCode, String strUserPassword, HttpServletRequest request )
    {
        // There is no login required : the user is supposed to be already authenticated
        return getHttpAuthenticatedUser( request );
    }

    @Override
    public void logout( AdminUser user )
    {
        // TODO Auto-generated method stub
    }

    @Override
    public AdminUser getAnonymousUser( )
    {
        throw new UnsupportedOperationException( "La methode getAnonymousUser() n'est pas encore implementee." );
    }

    @Override
    public boolean isExternalAuthentication( )
    {
        return true;
    }

    @Override
    public AdminUser getHttpAuthenticatedUser( HttpServletRequest request )
    {
        AdminUser user = null;
        user = AdminUserService.getAdminUser( request );

        if ( user == null )
        {
            HttpSession session = request.getSession( true );
            session.setAttribute( "luteceAdminLoginNextUrl", getLoginPageUrl( ) );
            return null;
        }

        // Reload User if info
        if ( user instanceof AdminOauth2User )
        {
            AdminOauth2User userOauth = (AdminOauth2User) user;
            if ( userOauth.getToken( ).getRefreshToken( ) != null )
            {
                AuthDataClient authDataClient = (AuthDataClient) DataClientService.instance( ).getClient( Oauth2Utils.AUTH_DATA_CLIENT_NAME );
                Token token = TokenService.getService( ).getTokenByRefreshToken( userOauth.getToken( ).getRefreshToken( ) );
                try
                {
                    Map<String, Object> mapUserInfo = authDataClient.parse( authDataClient.getData( token ) );
                    return Oauth2Service.getInstance( ).processAuthentication( request, mapUserInfo, token );
                }
                catch( IOException e )
                {
                    AppLogService.error( "error during retrieving user info with refresh token  ", e );
                }
                catch( AccessDeniedException | UserNotSignedException e )
                {
                    // Not an error : the user is not authenticated or does not have the rights to access the application
                    throw new RuntimeException( e );
                }

            }
        }

        return user;
    }

    @Override
    public String getLoginPageUrl( )
    {
        return Oauth2Utils.getAuthClientConf( ).getRedirectUri( );
    }

    @Override
    public String getChangePasswordPageUrl( )
    {
        return AppPropertiesService.getProperty(Oauth2Utils.OAUTH2_CHANGE_PASSWORD_URL,null);
    }

    @Override
    public String getDoLoginUrl( )
    {
        return getLoginPageUrl( );
    }

    @Override
    public String getDoLogoutUrl( )
    {
        return Oauth2Utils.getAuthServerConf( ).getLogoutEndpointUri( );
    }

    @Override
    public String getNewAccountPageUrl( )
    {
        return AppPropertiesService.getProperty(Oauth2Utils.OAUTH2_NEW_ACCOUNT_URL,null);
    }

    @Override
    public String getViewAccountPageUrl( )
    {
        return AppPropertiesService.getProperty(Oauth2Utils.OAUTH2_VIEW_ACCOUNT_URL,null);
    }

    @Override
    public String getLostPasswordPageUrl( )
    {
        return AppPropertiesService.getProperty(Oauth2Utils.OAUTH2_LOST_PASSWORD_URL,null);
    }

    @Override
    public String getLostLoginPageUrl( )
    {
        return AppPropertiesService.getProperty(Oauth2Utils.OAUTH2_LOST_LOGIN_URL,null);
    }

    @Override
    public Collection<AdminUser> getUserList( String s, String s1, String s2 )
    {
        // TODO Auto-generated method stub
        return new ArrayList<>( );
    }

    @Override
    public AdminUser getUserPublicData( String strId )
    {
        // TODO Auto-generated method stub
        return null;
    }

}
