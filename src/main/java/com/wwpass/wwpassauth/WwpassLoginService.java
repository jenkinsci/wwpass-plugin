/**
 * com.wwpass.wwpassauth.WwpassLoginService.java
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

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Failure;
import hudson.model.User;
import hudson.security.FederatedLoginService;
import hudson.security.FederatedLoginServiceUserProperty;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import static com.wwpass.wwpassauth.WwpassUtils.*;



/**
 * Implementation of <code>FederatedLoginService</code> provides Authentication via WWPass system
 */
@Extension
public class WwpassLoginService extends FederatedLoginService {

    private static final Logger LOGGER = Logger.getLogger(WwpassLoginService.class.getName());

    private String name;

    public WwpassLoginService() {
        super();
    }

    @DataBoundConstructor
    public WwpassLoginService(String name) {
        super();
        this.name = name;
    }

    private String getCertFile() {

        String certFile = getDescriptor().getCertFile();

        if (certFile == null || certFile.isEmpty()) {
            if (System.getProperty("os.name").startsWith("Windows")) {
                certFile = DEFAULT_CERT_FILE_WINDOWS;
            } else if (System.getProperty("os.name").startsWith("Linux")) {
                certFile = DEFAULT_CERT_FILE_LINUX;
            } else {
                LOGGER.severe(Messages.WwpassSession_UnsupportedOsError());
                throw new Failure(Messages.WwpassSession_AuthError());
            }
        }

        return certFile;
    }

    private String getKeyFile() {

        String keyFile = getDescriptor().getKeyFile();

        if (keyFile == null || keyFile.isEmpty()) {
            if (System.getProperty("os.name").startsWith("Windows")) {
                keyFile = DEFAULT_KEY_FILE_WINDOWS;
            } else if (System.getProperty("os.name").startsWith("Linux")) {
                keyFile = DEFAULT_KEY_FILE_LINUX;
            } else {
                LOGGER.severe(Messages.WwpassSession_UnsupportedOsError());
                throw new Failure(Messages.WwpassSession_AuthError());
            }
        }

        return keyFile;
    }

    @Override
    public String getUrlName() {
        return "wwpass";
    }

    public Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass() {
        return WwpassUserProperty.class;
    }

    public HttpResponse doStartLogin(@QueryParameter String ticket, @QueryParameter final String from)
            throws IOException, GeneralSecurityException {

        String puid = authenticateInWwpass(ticket, getCertFile(), getKeyFile());

        WwpassIdentityImpl id = new WwpassIdentityImpl(new WwpassIdentity(puid));
        User u = id.signin();

        return HttpResponses.redirectToContextRoot();
    }

    public HttpResponse doStartAssociate(@QueryParameter String ticket) throws IOException {

        String puid = authenticateInWwpass(ticket, getCertFile(), getKeyFile());

        WwpassIdentityImpl id = new WwpassIdentityImpl(new WwpassIdentity(puid));

        if (id.locateUser() == null) {
            id.addToCurrentUser();
            //return new HttpRedirect("onAssociationSuccess");
            return new HttpRedirect(Jenkins.getInstance().getRootUrlFromRequest() + "user/" + Jenkins.getAuthentication().getName() + "/configure");
        } else {
            return new HttpRedirect("onAssociationError");
        }

    }
    
    public HttpResponse doGetTicket() throws IOException {
        return getJsonTicket("", getCertFile(), getKeyFile());
    }

    private String getName() {
        return WwpassUtils.getName(getCertFile(),getKeyFile());
    }

    public DescriptorImpl getDescriptor()
    {
        return (DescriptorImpl) Descriptor.find(DescriptorImpl.class.getName());
    }

    public class WwpassIdentityImpl extends FederatedLoginService.FederatedIdentity {
        private final WwpassIdentity id;

        public WwpassIdentityImpl(WwpassIdentity id) {
            this.id = id;
        }

        @Override
        public String getIdentifier() {
            return id.getPuid();
        }

        @Override
        public String getNickname() {
            return id.getEffectiveNick();
        }

        @Override
        public String getFullName() {
            return id.getFullname();
        }

        @Override
        public String getEmailAddress() {
            return id.getEmail();
        }

        @Override
        public String getPronoun() {
            return "WWPass ID";
        }
    }
    @Extension
    public static class DescriptorImpl extends GlobalConfiguration {

        public DescriptorImpl()
        {
            load();
        }

        @Override
        public String getDisplayName() {
            return "WWPass Plugin LoginService";
        }

        private String certFile;
        private String keyFile;
        private String name;

        @Override
        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
            this.certFile = json.getString("certFile");
            this.keyFile = json.getString("keyFile");
            this.name = json.getString("name");

            save();
            return super.configure(req, json);    //To change body of overridden methods use File | Settings | File Templates.
        }

        public String getCertFile() {

            if (certFile == null || certFile.isEmpty()) {
                if (System.getProperty("os.name").startsWith("Windows")) {
                    certFile = DEFAULT_CERT_FILE_WINDOWS;
                } else if (System.getProperty("os.name").startsWith("Linux")) {
                    certFile = DEFAULT_CERT_FILE_LINUX;
                } else {
                    LOGGER.severe(Messages.WwpassSession_UnsupportedOsError());
                    throw new Failure(Messages.WwpassSession_AuthError());
                }
            }

            return certFile;
        }
        public String getKeyFile() {
            if (keyFile == null || keyFile.isEmpty()) {
                if (System.getProperty("os.name").startsWith("Windows")) {
                    keyFile = DEFAULT_KEY_FILE_WINDOWS;
                } else if (System.getProperty("os.name").startsWith("Linux")) {
                    keyFile = DEFAULT_KEY_FILE_LINUX;
                } else {
                    LOGGER.severe(Messages.WwpassSession_UnsupportedOsError());
                    throw new Failure(Messages.WwpassSession_AuthError());
                }
            }

            return keyFile;
        }
        public String getName() {
            String name = WwpassUtils.getName(getCertFile(), getKeyFile());

            if (name == null || name.isEmpty()) {
                return this.name;
            } else {
                return name;
            }
        }
    }
}
