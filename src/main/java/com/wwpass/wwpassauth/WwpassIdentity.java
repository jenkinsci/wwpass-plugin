/**
 * com.wwpass.wwpassauth.WwpassIdentity.java
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

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.logging.Level;
import java.util.logging.Logger;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.SecurityRealm;

import jenkins.model.Jenkins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;



public class WwpassIdentity extends UserProperty implements UserDetails{

    private static final Logger LOGGER = Logger.getLogger(WwpassIdentity.class.getName());

    private final String puid;

    private String nickname;
    private String email;
    private String fullname;

    private boolean activated;

    private static final GrantedAuthority[] TEST_AUTHORITY = {SecurityRealm.AUTHENTICATED_AUTHORITY};

    public WwpassIdentity(String puid) {
        this.puid = puid;
        this.activated = false;
    }

    public WwpassIdentity(User u, String puid) {
        this.puid = puid;
        this.fullname = u.getFullName();
        this.nickname = u.getId();

    }

    public void populate(WwpassSecurityRealm.SignupInfo si) {
        this.email = si.email;
        this.fullname = si.fullname;
        this.nickname = si.nickname;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPuid() {
        return puid;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

    public String getFullname() {
        return fullname;
    }

    /**
     * Obtains the token suitable as the user ID.
     */
    public String getEffectiveNick() {
        if (getNickname()!=null)     return getNickname();
        if (getEmail()!=null)    return getEmail();
        return getPuid();
    }

    /**
     * Updates the user information on Hudson based on the information in this identity.
     */
    public void updateProfile(User u) throws IOException {
        // update the user profile by the externally given information
        if (getFullname()!=null)
            u.setFullName(getFullname());
        if (getEmail()!=null) {
            try {
                // legacy hack. mail support has moved out to a separate plugin
                Class<?> up = Jenkins.getInstance().pluginManager.uberClassLoader.loadClass("hudson.tasks.Mailer$UserProperty");
                Constructor<?> c = up.getDeclaredConstructor(String.class);
                u.addProperty((UserProperty)c.newInstance(getEmail()));
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to set the e-mail address",e);
            }
        }
    }

    public void activate() {
        this.activated = true;
    }
    /**
     * Returns the authorities granted to the user. Cannot return <code>null</code>.
     *
     * @return the authorities (never <code>null</code>)
     */
    @Override
    public GrantedAuthority[] getAuthorities() {
        return TEST_AUTHORITY;
    }

    /**
     * This implementation doesn't support password. This realm uses WWPass Key instead of password.
     */
    @Override
    public String getPassword() {
        return null;
    }

    /**
     * Returns the username used to authenticate the user. Cannot return <code>null</code>.
     *
     * @return the puid instead of username (never <code>null</code>)
     */
    @Override
    public String getUsername() {
        return getPuid();
    }

    /**
     * Indicates whether the user's account has expired. An expired account cannot be authenticated.
     *
     * @return <code>true</code> if the user's account is valid (ie non-expired), <code>false</code> if no longer valid
     *         (ie expired)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked. A locked user cannot be authenticated.
     * User account had been disabled until administrator activate it.
     *
     * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
     */
    @Override
    public boolean isAccountNonLocked() {
        return activated;
    }

    /**
     * Indicates whether the user's credentials (password) has expired. Expired credentials prevent
     * authentication.
     *
     * @return <code>true</code> if the user's credentials are valid (ie non-expired), <code>false</code> if no longer
     *         valid (ie expired)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is enabled or disabled. A disabled user cannot be authenticated.
     * User account had been disabled until administrator activate it.
     *
     * @return <code>true</code> if the user is enabled, <code>false</code> otherwise
     */
    @Override
    public boolean isEnabled() {
        return activated;
    }
    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public WwpassIdentity newInstance(User user) {
            WwpassIdentity wi = user.getProperty(WwpassIdentity.class);
            return wi;
        }

        @Override
        public boolean isEnabled() {
            return Jenkins.getInstance().getSecurityRealm() instanceof WwpassSecurityRealm;
            //return true;
        }

        @Override
        public String getDisplayName() {
            return "WWPass ID";
        }
    }
}
