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
package fr.paris.lutece.plugins.adminauthenticationoauth2.service.session;

import fr.paris.lutece.plugins.adminauthenticationoauth2.service.Oauth2Utils;
import fr.paris.lutece.portal.service.spring.SpringContextService;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Oauth2AdminUserSessionService implements IOauth2AdminUserSessionService
{
    public static final String BEAN_LUTECE_USER_SESSION_SERVICE = "adminauthenticationoauth2.oauth2AdminUserSessionService";

    private static IOauth2AdminUserSessionService _singleton;
    private static Map<String, Oauth2AdminUserSession> _hashSession;
    private static Map<String, Set<String>> _hashAdminUserName;

    public static IOauth2AdminUserSessionService getInstance( )
    {
        if ( _singleton == null )
        {
            _singleton = SpringContextService.getBean( BEAN_LUTECE_USER_SESSION_SERVICE );
            _hashSession = new HashMap<>( );
            _hashAdminUserName = new HashMap<>( );
        }

        return _singleton;
    }

    public boolean isAdminUserUpToDate( String strSession )
    {
        if ( _hashSession.containsKey( strSession ) && !_hashSession.get( strSession ).isUpToDate( ) )
        {
            _hashSession.get( strSession ).setUpToDate( true );

            return false;
        }

        return true;
    }

    public void addAdminUserSession( String strAdminUserName, String strSession )
    {
        _hashAdminUserName.putIfAbsent( strAdminUserName, new HashSet<>( ) );
        _hashAdminUserName.get( strAdminUserName ).add( strSession );
        _hashSession.put( strSession, new Oauth2AdminUserSession( strSession, strAdminUserName, true ) );
    }

    public void removeAdminUserSession( String strSession )
    {
        if ( _hashSession.containsKey( strSession ) )
        {
            String strAdminUserName = _hashSession.get( strSession ).getAdminUserName( );
            _hashSession.remove( strSession );

            if ( _hashAdminUserName.containsKey( strAdminUserName ) )
            {
                _hashAdminUserName.get( strAdminUserName ).remove( strSession );

                if ( _hashAdminUserName.get( strAdminUserName ).isEmpty( ) )
                {
                    _hashAdminUserName.remove( strAdminUserName );
                }
            }
        }
    }

    public void notifyAdminUserUpdating( String strAdminUserName )
    {
        if ( _hashAdminUserName.containsKey( strAdminUserName ) )
        {
            Set<String> setSession = _hashAdminUserName.get( strAdminUserName );

            for ( String strSession : setSession )
            {
                if ( _hashSession.containsKey( strSession ) )
                {
                    _hashSession.get( strSession ).setUpToDate( false );
                }
            }
        }
    }
}
