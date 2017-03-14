/**
 * com.wwpass.wwpassauth.WwpassAuthenticationToken.java
 *
 * WWPass Client Library
 *
 * @copyright (c) WWPass Corporation, 2013
 * @author Stanislav Panyushkin <s.panyushkin@wwpass.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.wwpass.wwpassauth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import hudson.security.SecurityRealm;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;


/**
 * Authentication token for <class>WwpassSecurityRealm</class>
 */
public class WwpassAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;
    private final String puid;
    private final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();


    public WwpassAuthenticationToken(String puid) {
        super(new GrantedAuthority[] {});

        this.puid = puid;

        setAuthenticated(false);

        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
    }

    public WwpassAuthenticationToken(String puid, GrantedAuthority[] authorities) {
        super(new GrantedAuthority[] {});

        this.puid = puid;

        setAuthenticated(true);

        this.authorities.addAll(Arrays.asList(authorities));
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return authorities.toArray(new GrantedAuthority[authorities.size()]);
    }

    /**
     * The credentials that prove the principal is correct. This is usually a password, but could be anything
     * relevant to the <code>AuthenticationManager</code>. Callers are expected to populate the credentials.
     *
     * @return always return empty string
     */
    @Override
    public Object getCredentials() {
        return "";
    }

    /**
     * The identity of the principal being authenticated. This is usually a username. Callers are expected to
     * populate the principal.
     *
     * @return the PUID provided by WWPass SPFE for this WWPass user and Service Provider pair
     */
    @Override
    public Object getPrincipal() {
        return puid;
    }
}
