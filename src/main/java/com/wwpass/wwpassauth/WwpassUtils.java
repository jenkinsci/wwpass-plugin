/**
 * com.wwpass.wwpassauth.WwpassUtils.java
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import hudson.model.Failure;

import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;

import com.wwpass.connection.WWPassConnection;
import com.wwpass.connection.exceptions.WWPassProtocolException;


public class WwpassUtils {
    private static final Logger LOGGER = Logger.getLogger(WwpassUtils.class.getName());

    public static final String DEFAULT_CERT_FILE_WINDOWS = "C:/wwpass/wwpass_sp.crt";
    public static final String DEFAULT_KEY_FILE_WINDOWS = "C:/wwpass/wwpass_sp.key";
    public static final String DEFAULT_CERT_FILE_LINUX = "/etc/ssl/certs/wwpass_sp.crt";
    public static final String DEFAULT_KEY_FILE_LINUX = "/etc/ssl/certs/wwpass_sp.key";
    public static final int DEFAULT_TICKET_TTL = 300;

    public static String authenticateInWwpass(String ticket, String certFile, String keyFile) {
        WWPassConnection conn = null;
        String puid;
        String newTicket;
        try {
            conn = new WWPassConnection(certFile, keyFile);
            newTicket = conn.putTicket(ticket);
            puid = conn.getPUID(newTicket);
        } catch (WWPassProtocolException e) {
            LOGGER.log(Level.SEVERE, "An error occurred while trying to get PUID: ", e);
            throw new Failure(Messages.WwpassSession_AuthError());
        } catch (FileNotFoundException e) {
            LOGGER.severe(Messages.WwpassSession_UnsupportedOsError() + "Specified file paths \"" + certFile + "\" or \"" + keyFile + "\" are wrong.");
            throw new Failure(Messages.WwpassSession_AuthError());
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "An error occurred while trying to get PUID: ", e);
            throw new Failure(Messages.WwpassSession_AuthError());
        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "An error occurred while trying to get PUID: ", e);
            throw new Failure(Messages.WwpassSession_AuthError());
        }
        if (puid == null) {
            LOGGER.severe("PUID cannot be null. ");
            throw new Failure(Messages.WwpassSession_AuthError());
        }
        return puid;
    }

    public static String getName(String certFile, String keyFile) {
        WWPassConnection conn;
        try {
            conn = new WWPassConnection(certFile, keyFile);
            return conn.getName();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "An error occurred while trying to get Service Provider's name: ", e);
            throw new Failure(Messages.WwpassSession_AuthError());
        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "An error occurred while trying to get Service Provider's name: ", e);
            throw new Failure(Messages.WwpassSession_AuthError());
        }
    }

    public static HttpResponse getJsonTicket(String authType, String certFile, String keyFile) {
        WWPassConnection conn;
        try {
            conn = new WWPassConnection(certFile, keyFile);
            String ticket = conn.getTicket(authType, DEFAULT_TICKET_TTL);
            return HttpResponses.plainText("{ " +
                        "\"ticket\": \"" + ticket + "\"" +
                        ", \"ttl\": " + DEFAULT_TICKET_TTL +
                    "}");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "An error occurred while trying to get WWPass ticket: ", e);
            throw new Failure(Messages.WwpassSession_AuthError());
        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "An error occurred while trying to get WWPass ticket: ", e);
            throw new Failure(Messages.WwpassSession_AuthError());
        }
    }
}
