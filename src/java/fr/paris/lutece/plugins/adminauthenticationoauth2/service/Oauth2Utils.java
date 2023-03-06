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
import fr.paris.lutece.plugins.oauth2.business.AuthClientConf;
import fr.paris.lutece.plugins.oauth2.business.AuthServerConf;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

/**
 * Constants
 */
public final class Oauth2Utils
{
    // Beans properties names
    public static final String AUTHENTICATION_BEAN_NAME = "adminauthenticationoauth2.authentication";
    private static final String BEAN_AUTH_SERVER_CONF = "oauth2.server";
    private static final String BEAN_AUTH_CLIENT_CONF = "oauth2.client";


    // OAuth2 properties names
    public static final String PROPERTY_USE_PROMPT_NONE = "adminauthenticationoauth2.usePromptNone";
    public static final String PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_URLS = "adminauthenticationoauth2.usePromptNoneWhiteListingUrls";
    public static final String PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_HEADERS = "adminauthenticationoauth2.usePromptNoneWhiteListingHeaders";
    public static final String PROPERTY_VALIDATE_REFRESH_TOKEN = "adminauthenticationoauth2.validateRefreshToken";
    public static final String PROPERTY_USER_KEY_NAME = "adminauthenticationoauth2.attributeKeyUsername";
    public static final String PROPERTY_IDENTITY_ATTRIBUTE_KEY = "adminauthenticationoauth2.attributeIdentityKey";
    public static final String PROPERTY_USER_MAPPING_ATTRIBUTES = "adminauthenticationoauth2.userMappingAttributes";
    public static final String PROPERTY_EMAIL_ATTRIBUTE_KEY = "adminauthenticationoauth2.attribute.user.business-info.online.email";
    public static final String PROPERTY_LASTNAME_ATTRIBUTE_KEY = "adminauthenticationoauth2.attribute.user.name.family";
    public static final String PROPERTY_FIRSTNAME_ATTRIBUTE_KEY = "adminauthenticationoauth2.attribute.user.name.given";
    public static final String CONSTANT_LUTECE_USER_PROPERTIES_PATH = "adminauthenticationoauth2.attribute";

    // urls properties names
    public static final String OAUTH2_CHANGE_PASSWORD_URL = "adminauthenticationoauth2.url.changePassword";
    public static final String OAUTH2_NEW_ACCOUNT_URL = "adminauthenticationoauth2.url.newAccount";
    public static final String OAUTH2_VIEW_ACCOUNT_URL = "adminauthenticationoauth2.url.viewAccount";
    public static final String OAUTH2_LOST_PASSWORD_URL = "adminauthenticationoauth2.url.lostPassword";
    public static final String OAUTH2_LOST_LOGIN_URL = "adminauthenticationoauth2.url.lostLogin";

    // Other properties names
    public static final String PROPERTY_AUTH_SERVICE_NAME = "adminauthenticationoauth2.service.name";

    // Simple constants
    public static final String AUTH_DATA_CLIENT_NAME = "authData";
    public static final String CONSTANT_ACTION_DOLOGOUT = "doLogout";
    public static final String CONSTANT_BO = "BO";
    public static final String URL_INTERROGATIVE = "?";
    public static final String URL_AMPERSAND = "&";
    public static final String URL_EQUAL = "=";
    public static final String URL_STAR = "*";
    public static final String SEPARATOR = ",";
    public static final String ERROR_TYPE_LOGIN_REQUIRED = "login_required";
    public static final String REINIT_ERROR_LOGIN = "reinit_error_login";
    public static final String SESSION_ERROR_LOGIN = "session_error_login";
    public static final String PARAM_ERROR_LOGIN = "error_login";
    public static final String PARAMETER_UID = AppPropertiesService.getProperty(PROPERTY_USER_KEY_NAME,"uid");


    // Beans
    private static AuthServerConf _authServerConf;
    private static AuthClientConf _authClientConf;
    private static AdminOauth2Authentication _authService;

    /** Private constructor */
    private Oauth2Utils( )
    {
    }

    public static AuthServerConf getAuthServerConf( )
    {
        if ( _authServerConf == null )
        {
            _authServerConf = SpringContextService.getBean( BEAN_AUTH_SERVER_CONF );
        }
        return _authServerConf;
    }

    public static AuthClientConf getAuthClientConf( )
    {
        if ( _authClientConf == null )
        {
            _authClientConf = SpringContextService.getBean( BEAN_AUTH_CLIENT_CONF );
        }
        return _authClientConf;
    }

    static AdminOauth2Authentication getAuthService()
    {
        if ( _authService == null )
        {
            _authService = SpringContextService.getBean( AUTHENTICATION_BEAN_NAME );
        }
        return _authService;
    }
}
