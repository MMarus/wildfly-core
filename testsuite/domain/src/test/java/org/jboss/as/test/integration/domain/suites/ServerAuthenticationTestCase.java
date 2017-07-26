/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.test.integration.domain.suites;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.helpers.domain.DomainClient;
import org.jboss.as.test.http.Authentication;
import org.jboss.as.test.integration.domain.extension.ExtensionSetup;
import org.jboss.as.test.integration.domain.management.util.DomainLifecycleUtil;
import org.jboss.as.test.integration.domain.management.util.DomainTestSupport;
import org.jboss.dmr.ModelNode;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.sasl.util.UsernamePasswordHashUtil;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.AUTHENTICATION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.CORE_SERVICE;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILED;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.HOST;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.HOST_STATE;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.LOCAL;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.MANAGEMENT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.NAME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.READ_ATTRIBUTE_OPERATION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.READ_RESOURCE_OPERATION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.REMOVE;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RUNTIME_CONFIGURATION_STATE;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SECURITY_REALM;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SERVER;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.Assert.assertEquals;

/**
 * @author Ken Wills
 *
 * Basic tests for domain server auth when local realm authentication is removed.
 */
public class ServerAuthenticationTestCase {

    private static DomainTestSupport testSupport;
    private static DomainLifecycleUtil domainMasterLifecycleUtil;
    private static DomainLifecycleUtil domainSlaveLifecycleUtil;

    @BeforeClass
    public static void setupDomain() throws Exception {
        DomainTestSupport.Configuration config =  DomainTestSupport.Configuration.create(ServerAuthenticationTestCase.class.getSimpleName(),
                "domain-configs/domain-minimal.xml", "host-configs/host-master.xml", "host-configs/host-minimal.xml");
        testSupport = DomainTestSupport.createAndStartSupport(config);
        domainMasterLifecycleUtil = testSupport.getDomainMasterLifecycleUtil();
        domainSlaveLifecycleUtil = testSupport.getDomainSlaveLifecycleUtil();
        ExtensionSetup.initialiseProfileIncludesExtension(testSupport);
    }

    @AfterClass
    public static void tearDownDomain() throws Exception {
        // add local auth back on the slave
        ServerAuthenticationTestCase.addLocalAuth(domainMasterLifecycleUtil.getDomainClient(), "slave");
        if (domainSlaveLifecycleUtil != null) {
            domainSlaveLifecycleUtil.stop();
            domainSlaveLifecycleUtil = null;
        }

        if (domainMasterLifecycleUtil != null) {
            domainMasterLifecycleUtil.stop();
            domainMasterLifecycleUtil = null;
        }
        testSupport.stop();
        testSupport = null;
    }

    @Test
    public void testDisableLocalAuthAndStartServers() throws Exception {
        DomainClient master = domainMasterLifecycleUtil.getDomainClient();
        String finalServerResult = "";

        // add a user we can re-auth with
        final String testName = ServerAuthenticationTestCase.class.getSimpleName();
        final File domains = new File("target" + File.separator + "domains" + File.separator + testName);
        final File masterDir = new File(domains, "slave");
        final File domainConfigDir = new File(masterDir, "configuration");
        addUser(domainConfigDir, "ManagementRealm", Authentication.USERNAME, Authentication.PASSWORD);

        removeLocalAuth(master, "slave");

        // don't reset the configs.
        domainSlaveLifecycleUtil.getConfiguration().setRewriteConfigFiles(false);

        domainSlaveLifecycleUtil.stop();
        // can't use start(), as the client can't auth
        domainSlaveLifecycleUtil.startAsync();
        final long time = System.currentTimeMillis() + 10000;
        do {
            Thread.sleep(250);
            if (lookupHostInModel(master, "slave")) {
                break;
            }
        } while (System.currentTimeMillis() < time);

        // verify local-auth is actually off on the slave
        final ModelNode localAuth = new ModelNode();
        localAuth.get(OP).set(READ_RESOURCE_OPERATION);
        localAuth.get(OP_ADDR).set(getLocalAuthPath("slave"));
        final ModelNode localAuthResult = master.execute(localAuth);
        assertEquals(FAILED, localAuthResult.get(OUTCOME).asString());
        //assertTrue(localAuthResult.get(FAILURE_DESCRIPTION).asString().startsWith("WFLYCTL0216:")); // WFLYCTL0216: Management resource not found

        // verify server connected and running
        final ModelNode servers = new ModelNode();
        servers.get(OP).set(READ_ATTRIBUTE_OPERATION);
        final PathAddress serverPath = PathAddress.pathAddress(HOST, "slave")
                .append(SERVER, "main-three"); // main-three is autostart = true
        servers.get(OP_ADDR).set(serverPath.toModelNode());
        servers.get(NAME).set(RUNTIME_CONFIGURATION_STATE);
        final ModelNode serverResult = master.execute(servers);
        assertEquals(SUCCESS, serverResult.get(OUTCOME).asString());
        assertEquals("ok", serverResult.get(RESULT).asString());
        finalServerResult = serverResult.get(RESULT).asString();

        // verify we actually got a result
        assertEquals("ok", finalServerResult);
    }

    private void addUser(final File domainConfigDir, final String realm, final String username, final String password) throws Exception {
        File usersFile = new File(domainConfigDir, "mgmt-users.properties");
        Files.write(usersFile.toPath(),
                (username + "=" + new UsernamePasswordHashUtil().generateHashedHexURP(username, realm, password.toCharArray()) + "\n")
                        .getBytes(StandardCharsets.UTF_8));
    }

    private ModelControllerClient createClient(final InetAddress host, final int port,
                                              final String username, final String password, final String securityRealmName) {

        final CallbackHandler callbackHandler = new CallbackHandler() {

            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback current : callbacks) {
                    if (current instanceof NameCallback) {
                        NameCallback ncb = (NameCallback) current;
                        ncb.setName(username);
                    } else if (current instanceof PasswordCallback) {
                        PasswordCallback pcb = (PasswordCallback) current;
                        pcb.setPassword(password.toCharArray());
                    } else if (current instanceof RealmCallback) {
                        RealmCallback rcb = (RealmCallback) current;
                        rcb.setText(rcb.getDefaultText());
                    } else {
                        throw new UnsupportedCallbackException(current);
                    }
                }
            }
        };
        return ModelControllerClient.Factory.create(host, port, callbackHandler);
    }

    private static ModelNode getLocalAuthPath(final String host) {
        PathAddress path = PathAddress.pathAddress(HOST, host)
                .append(CORE_SERVICE, MANAGEMENT)
                .append(SECURITY_REALM, "ManagementRealm")
                .append(AUTHENTICATION, LOCAL);
        return path.toModelNode();
    }

    private static void removeLocalAuth(final DomainClient client, final String host) throws Exception {
        // remove local auth, requires restart
        final ModelNode op = new ModelNode();
        op.get(OP).set(REMOVE);
        op.get(OP_ADDR).set(getLocalAuthPath(host));
        final ModelNode result = client.execute(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString());
    }

    private static void addLocalAuth(final DomainClient client, final String host) throws Exception {
        // remove local auth, requires restart
        final ModelNode op = new ModelNode();
        op.get(OP).set(ADD);
        op.get(OP_ADDR).set(getLocalAuthPath(host));
        op.get("default-user").set("$local");
        op.get("skip-group-loading").set("true");
        final ModelNode result = client.execute(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString());
    }

    protected boolean lookupHostInModel(final ModelControllerClient client, final String host) throws Exception {
        final ModelNode operation = new ModelNode();
        operation.get(OP).set(READ_ATTRIBUTE_OPERATION);
        operation.get(OP_ADDR).add(HOST, host);
        operation.get(NAME).set(HOST_STATE);

        try {
            final ModelNode result = client.execute(operation);
            if (result.get(OUTCOME).asString().equals(SUCCESS)){
                final ModelNode model = result.require(RESULT);
                if (model.asString().equalsIgnoreCase("running")) {
                    return true;
                }
            }
        } catch (IOException e) {
            //
        }
        return false;
    }
}
