/**
 * com.wwpass.wwpassauth.WwpassSecurityRealm.java
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
import hudson.model.*;
import hudson.security.*;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.*;
import org.springframework.dao.DataAccessException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static com.wwpass.wwpassauth.WwpassUtils.*;


public class WwpassSecurityRealm extends SecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(WwpassSecurityRealm.class.getName());


    private final String certFile;
    private final String keyFile;
    private final String name;

    /**
     * If true, sign up is not allowed.
     * <p>
     * This is a negative switch so that the default value 'false' remains compatible with older installations.
     */
    private final boolean disableSignup;

    @DataBoundConstructor
    public WwpassSecurityRealm(String certFile, String keyFile, String name, boolean allowsSignup) {

        this.disableSignup = !allowsSignup;

        this.name = name;

        if (certFile != null && !certFile.isEmpty() && keyFile != null && !keyFile.isEmpty()) {
            this.certFile = certFile;
            this.keyFile = keyFile;
        } else {
            if (System.getProperty("os.name").startsWith("Windows")) {
                this.certFile = DEFAULT_CERT_FILE_WINDOWS;
                this.keyFile = DEFAULT_KEY_FILE_WINDOWS;
            } else if (System.getProperty("os.name").startsWith("Linux")) {
                this.certFile = DEFAULT_CERT_FILE_LINUX;
                this.keyFile = DEFAULT_KEY_FILE_LINUX;
            } else {
                LOGGER.severe(Messages.WwpassSession_UnsupportedOsError());
                throw new Failure(Messages.WwpassSession_AuthError());
            }
        }

        if(!hasSomeUser()) {
            // if Hudson is newly set up with the security realm and there's no user account created yet,
            // insert a filter that asks the user to create one
            try {
                PluginServletFilter.addFilter(CREATE_FIRST_USER_FILTER);
            } catch (ServletException e) {
                throw new AssertionError(e); // never happen because our Filter.init is no-op
            }
        }

    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof WwpassAuthenticationToken) {
                            return authentication;
                        }
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                }
        );
    }


    @Override
    public WwpassIdentity loadUserByUsername(String puid) throws UsernameNotFoundException, DataAccessException {
        Collection<User> all = User.getAll();

        for (User u : all) {
            WwpassIdentity p = u.getProperty(WwpassIdentity.class);
            if (puid.equals(p != null ? p.getPuid() : null)) {
                return p;
            }
        }

        throw new UsernameNotFoundException("There is no any user with: " + puid);

    }

    /**
     * Retrieves information about a group by its name.
     * <p/>
     * Groups is not suppoter by this implementation
     *
     * @return always throw the <code>UsernameNotFoundException</code>
     */
    public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
        throw new UsernameNotFoundException(groupname);
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/login";
    }

    public String getName() {

        String name = WwpassUtils.getName(certFile, keyFile);

        if (name == null || name.isEmpty()) {
            return this.name;
        } else {
            return name;
        }

    }

    public String getKeyFile() {
        return keyFile;
    }

    public String getCertFile() {
        return certFile;
    }

    /**
     * The login process starts from here.
     */
    public HttpResponse doCommenceLogin(StaplerRequest req, StaplerResponse rsp, @QueryParameter String from, @QueryParameter String ticket)
            throws ServletException, IOException {

        //TODO write login method
        String puid = authenticateInWwpass(ticket, certFile, keyFile);

        WwpassIdentity u;
        try {
            u = loadUserByUsername(puid);
        } catch(UsernameNotFoundException e) {
            if (allowsSignup()) {
                req.setAttribute("errorMessage",Messages.WwpassSecurityRealm_NoSuchUserAllowsSignup());
            } else {
                req.setAttribute("errorMessage",Messages.WwpassSecurityRealm_NoSuchUserDisableSignup());
            }
            req.getView(this, "login.jelly").forward(req,rsp);
            throw e;
        }
        if (!u.isAccountNonLocked() || !u.isEnabled()) {
            //throw new LockedException("Account is not activated for " + puid);
            throw new Failure(Messages.WwpassSecurityRealm_AccountNotActivated());
        }

        Authentication a = new WwpassAuthenticationToken(u.getNickname());
        a = this.getSecurityComponents().manager.authenticate(a);
        SecurityContextHolder.getContext().setAuthentication(a);

        return new HttpRedirect(Jenkins.getInstance().getRootUrl());
    }

    /**
     * Lets the current user silently login as the given user and report back accordingly.
     */
    @SuppressWarnings("ACL.impersonate")
    private void loginAndTakeBack(StaplerRequest req, StaplerResponse rsp, User u) throws ServletException, IOException {
        // ... and let him login
        Authentication a = new WwpassAuthenticationToken(u.getId());
        a = this.getSecurityComponents().manager.authenticate(a);
        SecurityContextHolder.getContext().setAuthentication(a);

        // then back to top
        req.getView(this,"success.jelly").forward(req,rsp);
    }

    /**
     * @return <code>null</code> if failed. The browser is already redirected to retry by the time this method returns.
     *      a valid {@link User} object if the user creation was successful.
     */
    private User createAccount(StaplerRequest req, StaplerResponse rsp,String formView) throws ServletException, IOException {

        SignupInfo si = new SignupInfo(req);

        String puid = authenticateInWwpass(si.ticket, certFile, keyFile);

        try {
            if (loadUserByUsername(puid) != null) {
                si.errorMessages.add(Messages.WwpassSecurityRealm_PuidIsAlreadyTaken());
            }
        } catch (UsernameNotFoundException e) {

        }

        if(si.nickname==null || si.nickname.length()==0)
            si.errorMessages.add(Messages.WwpassSecurityRealm_NicknameIsRequired());
        else {
            User user = User.get(si.nickname, false);
            if (null != user)
                if (user.getProperty(WwpassIdentity.class) != null)
                    si.errorMessages.add(Messages.WwpassSecurityRealm_NicknameIsAlreadyTaken());
        }

        if(si.fullname==null || si.fullname.length()==0)
            si.errorMessages.add(Messages.WwpassSecurityRealm_FullnameIsRequired());
        else {
            User user = User.get(si.fullname, false);
            if (null != user)
                if (user.getProperty(WwpassIdentity.class) != null)
                    si.errorMessages.add(Messages.WwpassSecurityRealm_FullnameIsAlreadyTaken());
        }

        if(si.email==null || !si.email.contains("@"))
            si.errorMessages.add(Messages.WwpassSecurityRealm_InvalidEmailAddress());

        if( !si.errorMessages.isEmpty() ) {
            // failed. ask the user to try again.
            req.setAttribute("data",si);
            req.getView(this, formView).forward(req,rsp);
            return null;
        }

        // register the user
        WwpassIdentity id = new WwpassIdentity(puid);
        id.populate(si);

        User user = createAccount(id);
        id.updateProfile(user);

        user.save();
        return user;
    }

    /**
     * Creates a new user account by registering a password to the user.
     */
    public User createAccount(WwpassIdentity id) throws IOException {
        User user = User.get(id.getNickname());
        user.addProperty(id);
        return user;
    }
    
    /**
     * Creates an user account. Used for self-registration.
     */
    public User doCreateAccount(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        return _doCreateAccount(req, rsp, "signup.jelly");
    }

    private User _doCreateAccount(StaplerRequest req, StaplerResponse rsp, String formView) throws ServletException, IOException {
        if(!allowsSignup())
            throw HttpResponses.error(SC_UNAUTHORIZED,new Exception("User sign up is prohibited"));

        boolean firstUser = !hasSomeUser();
        User u = createAccount(req, rsp, formView);
        if(u!=null) {
            if(firstUser)
                tryToMakeAdmin(u);  // the first user should be admin, or else there's a risk of lock out
            loginAndTakeBack(req, rsp, u);
        }
        return u;
    }

    /**
     * Creates a first admin user account.
     *
     * <p>
     * This can be run by anyone, but only to create the very first user account.
     */
    public void doCreateFirstAccount(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        if(hasSomeUser()) {
            rsp.sendError(SC_UNAUTHORIZED,"First user was already created");
            return;
        }
        User u = createAccount(req, rsp, "firstUser.jelly");
        if (u!=null) {
            tryToMakeAdmin(u);
            loginAndTakeBack(req, rsp, u);
        }
    }

    /**
     * Try to make this user a super-user
     */
    private void tryToMakeAdmin(User u) throws IOException {
        WwpassIdentity p = u.getProperty(WwpassIdentity.class);
        p.activate();
        u.save();
        AuthorizationStrategy as = Jenkins.getInstance().getAuthorizationStrategy();

        for (PermissionAdder adder : Jenkins.getInstance().getExtensionList(PermissionAdder.class)) {
            if (adder.add(as, u, Jenkins.ADMINISTER)) {
                return;
            }
        }
        LOGGER.severe("Admin permission wasn't added for user: " + u.getFullName() + ", ID: " + u.getId());
    }

    @Override
    public boolean allowsSignup() {
        return !disableSignup;
    }

    /**
     * Computes if this Jenkins has some user accounts configured.
     *
     * <p>
     * This is used to check for the initial
     */
    private static boolean hasSomeUser() {
        for (User u : User.getAll())
            if(u.getProperty(WwpassIdentity.class)!=null)
                return true;
        return false;
    }

    private static final Filter CREATE_FIRST_USER_FILTER = new Filter() {
        public void init(FilterConfig config) throws ServletException {
        }

        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            HttpServletRequest req = (HttpServletRequest) request;

            if(req.getRequestURI().equals(req.getContextPath()+"/")) {
                if (needsToCreateFirstUser()) {
                    ((HttpServletResponse)response).sendRedirect("securityRealm/firstUser");
                } else {// the first user already created. the role of this filter is over.
                    PluginServletFilter.removeFilter(this);
                    chain.doFilter(request,response);
                }
            } else
                chain.doFilter(request,response);

        }

        private boolean needsToCreateFirstUser() {
            return !hasSomeUser()
                    && Jenkins.getInstance().getSecurityRealm() instanceof WwpassSecurityRealm;
        }

        public void destroy() {
        }
    };


    public static final class SignupInfo {

        public String nickname, fullname, email, ticket;

        /**
         * To display an error messages, set its here.
         */
        public List<String> errorMessages = new ArrayList<String>();

        public SignupInfo() {
        }

        public SignupInfo(StaplerRequest req) {
            req.bindParameters(this);
        }

        public SignupInfo(FederatedLoginService.FederatedIdentity i) {
            this.fullname = i.getFullName();
            this.email = i.getEmailAddress();
        }
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getDisplayName() {
            return "WWPass Authentication";
        }
    }
}
