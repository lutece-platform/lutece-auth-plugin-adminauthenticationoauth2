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
package fr.paris.lutece.plugins.adminauthenticationoauth2.service;

import fr.paris.lutece.plugins.adminauthenticationoauth2.business.authentication.AdminOauth2Authentication;
import fr.paris.lutece.plugins.adminauthenticationoauth2.business.authentication.AdminOauth2User;
import fr.paris.lutece.plugins.adminauthenticationoauth2.service.session.Oauth2AdminUserSessionService;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.portal.service.admin.AccessDeniedException;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.security.UserNotSignedException;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Oauth2 Service.
 */
public final class Oauth2Service
{
    /** The attribute user mapping. */
    private static Map<String, List<String>> ATTRIBUTE_USER_MAPPING;

    /** The attribute user key name. */
    private static String [ ] ATTRIBUTE_USER_KEY_NAME;

    /** The singleton. */
    private static Oauth2Service _singleton;

    /**
     * private constructor.
     */
    private Oauth2Service( )
    {
    }

    /**
     * Gets the instance.
     *
     * @return the instance
     */
    public static Oauth2Service getInstance( )
    {
        if ( _singleton == null )
        {

            _singleton = new Oauth2Service( );
            String strTabUserKey = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_USER_KEY_NAME );
            if ( StringUtils.isNotBlank( strTabUserKey ) )
            {
                ATTRIBUTE_USER_KEY_NAME = strTabUserKey.split( Oauth2Utils.SEPARATOR );
            }
            String strUserMappingAttributes = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_USER_MAPPING_ATTRIBUTES );
            ATTRIBUTE_USER_MAPPING = new HashMap<>( );

            if ( StringUtils.isNotBlank( strUserMappingAttributes ) )
            {
                String [ ] tabUserProperties = strUserMappingAttributes.split( Oauth2Utils.SEPARATOR );
                String [ ] tabPropertiesValues;
                String userProperties;

                for ( int i = 0; i < tabUserProperties.length; i++ )
                {
                    userProperties = AppPropertiesService.getProperty( Oauth2Utils.CONSTANT_LUTECE_USER_PROPERTIES_PATH + "." + tabUserProperties [i] );

                    if ( StringUtils.isNotBlank( userProperties ) )
                    {

                        if ( userProperties.contains( Oauth2Utils.SEPARATOR ) )
                        {
                            tabPropertiesValues = userProperties.split( Oauth2Utils.SEPARATOR );

                            for ( int n = 0; i < tabPropertiesValues.length; n++ )
                            {
                                ATTRIBUTE_USER_MAPPING.computeIfAbsent( tabPropertiesValues [n], k -> ATTRIBUTE_USER_MAPPING.put( k, new ArrayList<>( ) ) );
                                ATTRIBUTE_USER_MAPPING.get( tabPropertiesValues [n] ).add( tabUserProperties [i] );
                            }

                        }
                        else
                        {

                            ATTRIBUTE_USER_MAPPING.computeIfAbsent( userProperties, k -> ATTRIBUTE_USER_MAPPING.put( k, new ArrayList<>( ) ) );
                            ATTRIBUTE_USER_MAPPING.get( userProperties ).add( tabUserProperties [i] );
                        }

                    }
                }
            }
        }

        return _singleton;
    }

    /**
     * Process the authentication.
     *
     * @param request
     *            The HTTP request
     * @param mapUserInfo
     *            the map user info
     * @param token
     *            the token
     * @return the oauth 2 user
     */
    public AdminOauth2User processAuthentication( HttpServletRequest request, Map<String, Object> mapUserInfo, Token token )
            throws AccessDeniedException, UserNotSignedException
    {

        // subject in user map
        if ( token.getIdToken( ) != null && token.getIdToken( ).getSubject( ) != null )
        {
            mapUserInfo.put( Oauth2Utils.PARAMETER_UID, token.getIdToken( ).getSubject( ) );

        }
        AdminOauth2User user = null;
        for ( String s : ATTRIBUTE_USER_KEY_NAME )
        {
            if ( mapUserInfo.containsKey( s ) )
            {
                user = new AdminOauth2User( (String) mapUserInfo.get( s ), token, Oauth2Utils.getAuthService( ) );
            }
        }

        if ( user != null )
        {

            for ( Entry<String, Object> entry : mapUserInfo.entrySet( ) )
            {
                if ( ATTRIBUTE_USER_MAPPING.containsKey( entry.getKey( ) ) )
                {
                    for ( String strUserInfo : ATTRIBUTE_USER_MAPPING.get( entry.getKey( ) ) )
                    {

                        Object val = entry.getValue( );
                        if ( val instanceof ArrayList<?> )
                        {

                            StringBuilder strBufVal = new StringBuilder( );
                            for ( Object tabVal : (ArrayList<?>) val )
                            {
                                strBufVal.append( tabVal.toString( ) );
                                strBufVal.append( Oauth2Utils.SEPARATOR );
                            }

                            if ( strBufVal.length( ) > 0 )
                            {
                                user.setUserInfo( strUserInfo, strBufVal.substring( 0, strBufVal.length( ) - 1 ) );
                            }

                            user.setUserInfo( strUserInfo, strBufVal.toString( ) );
                        }
                        else
                        {
                            user.setUserInfo( strUserInfo, (String) val );
                        }
                    }
                }
            }

            // add Identities Information
            // get Identity key the default key is the value of lutece username
            String strIdentityKey = user.getAccessCode( );
            String strIdentityKeyAttribute = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_IDENTITY_ATTRIBUTE_KEY );
            if ( strIdentityKeyAttribute != null && mapUserInfo.containsKey( strIdentityKeyAttribute ) )
            {
                strIdentityKey = mapUserInfo.get( strIdentityKeyAttribute ).toString( );
            }

            user.setAccessCode( strIdentityKey );

            String strEmailKeyAttribute = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_EMAIL_ATTRIBUTE_KEY );
            if ( strEmailKeyAttribute != null && mapUserInfo.containsKey( strEmailKeyAttribute ) )
            {
                user.setEmail( mapUserInfo.get( strEmailKeyAttribute ).toString( ) );
            }

            String strLastNameKeyAttribute = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_LASTNAME_ATTRIBUTE_KEY );
            if ( strLastNameKeyAttribute != null && mapUserInfo.containsKey( strLastNameKeyAttribute ) )
            {
                user.setLastName( mapUserInfo.get( strLastNameKeyAttribute ).toString( ) );
            }

            String strFirstNameKeyAttribute = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_FIRSTNAME_ATTRIBUTE_KEY );
            if ( strFirstNameKeyAttribute != null && mapUserInfo.containsKey( strFirstNameKeyAttribute ) )
            {
                user.setFirstName( mapUserInfo.get( strFirstNameKeyAttribute ).toString( ) );
            }

            // add Oauth2AdminUserSessionService session
            Oauth2AdminUserSessionService.getInstance( ).addAdminUserSession( user.getAccessCode( ), request.getSession( true ).getId( ) );
        }

        if ( user != null && user.getAccessCode( ) != null )
        {
            AdminUser bindUser = AdminUserHome.findUserByLogin( user.getAccessCode( ) );
            if ( bindUser == null )
            {
                if ( user.getLastName( ) == null )
                {
                    user.setLastName( "" );
                }
                if ( user.getFirstName( ) == null )
                {
                    user.setFirstName( "" );
                }
                AdminUserHome.create( user );
            }
            AdminAuthenticationService.getInstance( ).registerUser( request, user );
        }

        return user;
    }

    /**
     * Inits the service
     */
    public void init( )
    {
        // Nothing to do
    }

    /**
     * Process the logout.
     *
     * @param request
     *            The HTTP request
     */
    public static void processLogout( HttpServletRequest request )
    {
        AppLogService.debug( "Process logout" );
        AdminAuthenticationService.getInstance( ).logoutUser( request );
    }

    /**
     * redirect after login or logout.
     *
     * @param request
     *            The HTTP request
     * @param response
     *            The HTTP response
     * @throws IOException
     *             if an error occurs
     */
    public static void redirect( HttpServletRequest request, HttpServletResponse response ) throws IOException
    {
        String strNextURL = AdminAuthenticationService.getInstance( ).getLoginNextUrl( request );
        AppLogService.debug( "Next URL : " + strNextURL );

        if ( strNextURL == null )
        {
            strNextURL = AppPathService.getBaseUrl( request ) + AppPathService.getAdminMenuUrl( );
        }

        strNextURL = response.encodeRedirectURL( strNextURL );

        response.sendRedirect( strNextURL );
    }

}
