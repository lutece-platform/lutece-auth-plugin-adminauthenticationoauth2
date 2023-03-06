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

import fr.paris.lutece.plugins.adminauthenticationoauth2.business.authentication.AdminOauth2Authentication;
import fr.paris.lutece.plugins.adminauthenticationoauth2.business.authentication.AdminOauth2User;
import fr.paris.lutece.plugins.adminauthenticationoauth2.service.session.Oauth2AdminUserSessionService;
import fr.paris.lutece.plugins.adminauthenticationoauth2.service.Oauth2Utils;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.plugins.oauth2.service.TokenService;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.portal.service.admin.AccessDeniedException;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.admin.AdminUserService;
import fr.paris.lutece.portal.service.security.UserNotSignedException;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.url.UrlItem;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ParisConnectLuteceFilters
 *
 */
public class AdminOauth2Filter implements Filter
{

    private boolean _bUsePromptNone;
    private boolean _bValidateRefreshToken;
    private List<String> _listUsePromptWhiteUrls;
    private Map<String, List<String>> _mapUsePromptWhiteHeaders;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void destroy( )
    {
        // nothing
    }

    /**
     *
     * {@inheritDoc}
     */
    @SuppressWarnings( "deprecation" )
    @Override
    public void doFilter( ServletRequest servletRequest, ServletResponse response, FilterChain chain ) throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse resp = (HttpServletResponse) response;
        if ( request != null && "GET".equals( request.getMethod( ) ) )
        {
            AdminUser user = AdminUserService.getAdminUser( request );

            if ( user == null && isUsePomptNoneForRequest( request ) )
            {
                HttpSession session = request.getSession( true );

                if ( ( session.getAttribute( Oauth2Utils.SESSION_ERROR_LOGIN ) == null && request.getParameter( Oauth2Utils.PARAM_ERROR_LOGIN ) == null )
                        || session.getAttribute( Oauth2Utils.SESSION_ERROR_LOGIN ) != null
                                && session.getAttribute( Oauth2Utils.SESSION_ERROR_LOGIN ).equals( Oauth2Utils.REINIT_ERROR_LOGIN ) )
                {
                    session.setAttribute( Oauth2Utils.SESSION_ERROR_LOGIN, "" );
                    String strRedirectLoginUrl = AdminAuthenticationService.getInstance( ).getLoginPageUrl( );

                    resp.sendRedirect( strRedirectLoginUrl );

                    return;
                }

                session.setAttribute( Oauth2Utils.SESSION_ERROR_LOGIN, Oauth2Utils.REINIT_ERROR_LOGIN );
            }
            else
                if ( _bValidateRefreshToken && user instanceof AdminOauth2User )
                {
                    AdminOauth2User oauth2User = (AdminOauth2User) user;
                    if ( oauth2User.getToken( ) != null && oauth2User.getToken( ).getRefreshToken( ) != null )
                    {
                        Token token = TokenService.getService( ).getTokenByRefreshToken( oauth2User.getToken( ).getRefreshToken( ) );
                        if ( token == null )
                        {

                            AdminAuthenticationService.getInstance( ).logoutUser( request );
                        }
                        else
                        {
                            oauth2User.setToken( token );
                        }
                    }
                    else
                    {
                        AdminAuthenticationService.getInstance( ).logoutUser( request );
                    }
                }
            if ( !Oauth2AdminUserSessionService.getInstance( ).isAdminUserUpToDate( request.getSession( true ).getId( ) ) )
            {

                AdminOauth2Authentication oauth2Authentication = SpringContextService.getBean( "adminauthenticationoauth2.authentication" );
                user = oauth2Authentication.getHttpAuthenticatedUser( request );

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
                }
                try
                {
                    AdminAuthenticationService.getInstance( ).registerUser( request, user );
                }
                catch( AccessDeniedException | UserNotSignedException e )
                {
                    throw new RuntimeException( e );
                }
            }

        }

        chain.doFilter( servletRequest, response );
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void init( FilterConfig config )
    {
        _bUsePromptNone = AppPropertiesService.getPropertyBoolean( Oauth2Utils.PROPERTY_USE_PROMPT_NONE, false );
        _bValidateRefreshToken = AppPropertiesService.getPropertyBoolean( Oauth2Utils.PROPERTY_VALIDATE_REFRESH_TOKEN, false );

        String strTabWhiteListingUrls = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_URLS );
        String strTabWhiteListingHeaders = AppPropertiesService.getProperty( Oauth2Utils.PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_HEADERS );
        if ( StringUtils.isNotBlank( strTabWhiteListingUrls ) )
        {
            _listUsePromptWhiteUrls = Arrays.asList( strTabWhiteListingUrls.split( Oauth2Utils.SEPARATOR ) );
        }
        if ( StringUtils.isNotBlank( strTabWhiteListingHeaders ) )
        {
            _mapUsePromptWhiteHeaders = new HashMap<>( );
            Arrays.stream( strTabWhiteListingHeaders.split( Oauth2Utils.SEPARATOR ) )
                    .forEach( x -> _mapUsePromptWhiteHeaders.put( x, Arrays.asList( AppPropertiesService
                            .getProperty( Oauth2Utils.PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_HEADERS + "." + x, "" ).split( Oauth2Utils.SEPARATOR ) ) ) );
        }

    }

    private boolean isUsePomptNoneForRequest( HttpServletRequest request )
    {
        boolean bReturn = true;
        if ( _bUsePromptNone )
        {
            // test headers white list
            if ( _mapUsePromptWhiteHeaders != null && _mapUsePromptWhiteHeaders.size( ) > 0 )
            {
                bReturn = _mapUsePromptWhiteHeaders.keySet( ).stream( ).noneMatch( x -> request.getHeader( x ) != null
                        && _mapUsePromptWhiteHeaders.get( x ).stream( ).anyMatch( v -> v.equalsIgnoreCase( request.getHeader( x ) ) ) );
            }
            // test url white List
            if ( bReturn && _listUsePromptWhiteUrls != null && !_listUsePromptWhiteUrls.isEmpty( ) )
            {
                bReturn = _listUsePromptWhiteUrls.stream( ).noneMatch( x -> matchUrl( request, x ) );
            }

        }
        else
        {
            bReturn = false;
        }

        return bReturn;

    }

    /**
     * method to test if the URL matches the pattern
     * 
     * @param request
     *            the request
     * @param strUrlPatern
     *            the pattern
     * @return true if the URL matches the pattern
     */
    private boolean matchUrl( HttpServletRequest request, String strUrlPatern )
    {
        boolean bMatch = false;

        if ( strUrlPatern != null )
        {
            UrlItem url = new UrlItem( getResquestedUrl( request ) );

            if ( strUrlPatern.contains( Oauth2Utils.URL_INTERROGATIVE ) )
            {
                for ( String strParamPatternValue : strUrlPatern.substring( strUrlPatern.indexOf( Oauth2Utils.URL_INTERROGATIVE ) + 1 )
                        .split( Oauth2Utils.URL_AMPERSAND ) )
                {
                    String [ ] arrayPatternParamValue = strParamPatternValue.split( Oauth2Utils.URL_EQUAL );

                    if ( request.getParameter( arrayPatternParamValue [0] ) != null )
                    {
                        url.addParameter( arrayPatternParamValue [0], request.getParameter( arrayPatternParamValue [0] ) );
                    }
                }
            }

            if ( strUrlPatern.contains( Oauth2Utils.URL_STAR ) )
            {
                String strUrlPaternLeftEnd = strUrlPatern.substring( 0, strUrlPatern.indexOf( Oauth2Utils.URL_STAR ) );
                String strAbsoluteUrlPattern = getAbsoluteUrl( request, strUrlPaternLeftEnd );
                bMatch = url.getUrl( ).startsWith( strAbsoluteUrlPattern );
            }
            else
            {
                String strAbsoluteUrlPattern = getAbsoluteUrl( request, strUrlPatern );
                bMatch = url.getUrl( ).equals( strAbsoluteUrlPattern );
            }
        }

        return bMatch;
    }

    /**
     * Returns the absolute url corresponding to the given one, if the later was found to be relative. An url starting with "http://" is absolute. A relative
     * url should be given relatively to the webapp root.
     *
     * @param request
     *            the http request (provides the base path if needed)
     * @param strUrl
     *            the url to transform
     * @return the corresonding absolute url
     *
     */
    private String getAbsoluteUrl( HttpServletRequest request, String strUrl )
    {
        if ( ( strUrl != null ) && !strUrl.startsWith( "http://" ) && !strUrl.startsWith( "https://" ) )
        {
            return AppPathService.getBaseUrl( request ) + strUrl;
        }
        else
        {
            return strUrl;
        }
    }

    /**
     * Return the absolute representation of the requested url
     *
     * @param request
     *            the http request (provides the base path if needed)
     * @return the requested url has a string
     *
     */
    private String getResquestedUrl( HttpServletRequest request )
    {
        return request.getRequestURL( ).toString( );
    }

}
