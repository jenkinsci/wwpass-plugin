/**
 * com.wwpass.wwpassauth.WwpassUserProperty.java
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
import java.util.Collections;
import java.util.List;
import java.util.Set;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.util.Secret;

import static hudson.Util.fixNull;

import jenkins.model.Jenkins;

import org.kohsuke.stapler.DataBoundConstructor;


public class WwpassUserProperty extends FederatedLoginServiceUserProperty {
    @DataBoundConstructor
    public WwpassUserProperty(Set<String> identifiers) {
        super(unencrypt(fixNull(identifiers)));
    }

    /**
     * Reverse the effect of {@link #getProtectedPuids()}.
     */
    private static List<String> unencrypt(Set<String> identifiers) {
        List<String> r = new ArrayList<String>();
        for (String id : identifiers)
            r.add(Secret.fromString(id).getPlainText());
        return r;
    }

    public List<Secret> getProtectedPuids() {
        List<Secret> r = new ArrayList<Secret>();
        for (String id : getIdentifiers())
            r.add(Secret.fromString(id));
        return r;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public UserProperty newInstance(User user) {
            return new WwpassUserProperty(Collections.<String>emptySet());
        }

        @Override
        public boolean isEnabled() {
            return (Jenkins.getInstance().getSecurityRealm() instanceof AbstractPasswordBasedSecurityRealm)
                    && !(Jenkins.getInstance().getSecurityRealm() instanceof WwpassSecurityRealm);
        }

        @Override
        public String getDisplayName() {
            return "WWPass Keyset";
        }

        public String getName() {
            WwpassLoginService wls = (WwpassLoginService) Jenkins.getInstance().getFederatedLoginService("wwpass");
            return wls.getDescriptor().getName();
        }

    }
}
