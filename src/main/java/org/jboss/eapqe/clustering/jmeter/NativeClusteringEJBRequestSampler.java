
package org.jboss.eapqe.clustering.jmeter;

import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.jboss.eapqe.clustering.jmeter.util.LogLoader;
import org.jboss.eapqe.clustering.jmeter.util.MiscHelpers;
import org.jboss.ejb.client.Affinity;
import org.jboss.ejb.client.EJBClient;
import org.jboss.ejb.client.EJBClientConnection;
import org.jboss.ejb.client.EJBClientContext;
import org.jboss.ejb.client.EJBIdentifier;
import org.jboss.ejb.client.EJBModuleIdentifier;
import org.jboss.ejb.client.StatelessEJBLocator;
import org.jboss.ejb.client.EJBTransportProvider;
import org.jboss.test.clusterbench.ejb.stateful.RemoteStatefulSB;
import org.jboss.test.clusterbench.ejb.stateful.RemoteStatefulSBImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.SaslMechanismSelector;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.concurrent.TimeUnit;

/**
 * Custom sampler for clustering scenarios. This sampler uses JBoss EJB client with a native proxy.
 * <p>
 * Each thread defined in JMeter test plan corresponds to one ClusteringEJBRequestSampler instance.
 * Each ClusteringEJBRequestSampler instance creates its own InitialContext and looks up {@link RemoteStatefulSB} bean.
 * <p>
 * Specific results validation is used.
 *
 * @author Michal Vinkler mvinkler@redhat.com
 * @author Richard Achmatowicz
 */
public class NativeClusteringEJBRequestSampler extends AbstractJavaSamplerClient implements Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(NativeClusteringEJBRequestSampler.class);

    private static boolean first = true;

    /**
     * Host parameter defined in JMeter test plan
     */
    private static final String HOST = "host";

    /**
     * Port parameter defined in JMeter test plan
     */
    private static final String PORT = "port";

    /**
     * Username parameter defined in JMeter test plan
     */
    private static final String USERNAME = "username";

    /**
     * Password parameter defined in JMeter test plan
     */
    private static final String PASSWORD = "password";

    /**
     * Counter for request validation.
     */
    private int serial = 0;

    /**
     * Name of this thread for logging purposes.
     * Format: Thread Group X-Y
     */
    private String threadName;

    /**
     * The application name of the deployed EJBs. This is typically the ear name without the .ear suffix.
     * However, the application name could be overridden in the application.xml of the EJB deployment on the server.
     */
    private String appName = "clusterbench-ee10";

    /**
     * This is the module name of the deployed EJBs on the server. This is typically the jar name of the
     * EJB deployment, without the .jar suffix, but can be overridden via the ejb-jar.xml.
     */
    private String moduleName = "clusterbench-ee10-ejb";

    /**
     * AS7 allows each deployment to have an (optional) distinct name. We haven't specified a distinct name for
     * our EJB deployment, so this is an empty string
     */
    private String distinctName = "";

    /**
     * Name of the user to be used for secured connection. The user needs to be added on EAP.
     */
    private String username;

    /**
     * Password for the username to be used for secured connection. The user needs to be added on EAP.
     */
    private String password;

    private String hosts;
    private String ports;
    private EJBClientContext ejbClientContext;
    private MiscHelpers miscHelpers;

    private MiscHelpers getMiscHelpers() {
        if (this.miscHelpers == null) {
            this.miscHelpers = new MiscHelpers();
        }
        return this.miscHelpers;
    }

    /**
     * Custom invocation timeout to be set for the EJB calls. If not set, default invocation timeout will be used.
     */
    private int invocationTimeout = 0;
    private RemoteStatefulSB session = null;

    // non-javadoc, see interface JavaSamplerClient
    public SampleResult runTest(JavaSamplerContext javaSamplerContext) {

        LogLoader.loadLogs();

        SampleResult sampleResult = new SampleResult();
        sampleResult.setSampleLabel("ClusterbenchEJBRequestStateful");

        if (session == null) {
            LOG.trace("{}: Serial {}: Creating NEW SFSB (session not yet created).", threadName, serial);
            if (!initSession(sampleResult)) {
                return sampleResult;
            }
        }

        int gotSerial = 0;

        LOG.trace("{}: Serial {}: Invoking the SFSB.", threadName, serial);

        try {
            sampleResult.sampleStart();
            gotSerial = session.getSerialAndIncrement();
            sampleResult.sampleEnd();
            LOG.trace("{}: Serial {}: After successful increment: StartTime: {} TimeStamp: {} EndTime: {} ElapsedTime: {}", threadName, serial, sampleResult.getStartTime(), sampleResult.getTimeStamp(), sampleResult.getEndTime(), sampleResult.getTime());
        } catch (Exception e) {
            //sampleResult.sampleEnd() cannot be called twice
            if (sampleResult.getStartTime() != 0 & sampleResult.getEndTime() == 0) {
                sampleResult.sampleEnd();
                sampleResult.setConnectTime(sampleResult.getTime());
            }

            LOG.error("{}: Serial {}: Error getting response: Resetting session.", threadName, serial, e);
            session = null;
            serial = 0;

            sampleResult.setResponseMessage(String.format("%s: Serial %d: Could not get valid response.", threadName, serial));
            sampleResult.setSuccessful(false);
            return sampleResult;
        }

        sampleResult.setConnectTime(sampleResult.getTime());
        LOG.trace("{}: Serial {}: Response time: {}, Received serial: {}", threadName, serial, sampleResult.getTime(), gotSerial);
        validateResponse(sampleResult, gotSerial);

        first = false;
        return sampleResult;
    }

    /**
     * Create a proxy for a SFSB from scratch using the EJBClient API. This will not use the JNSI specific
     * control flow provided by the NamingEJBClientInterceptor.
     *
     * @param sampleResult
     * @return
     */
    private boolean initSession(SampleResult sampleResult) {
        // The EJB name which by default is the simple class name of the bean implementation class
        String beanName = RemoteStatefulSBImpl.class.getSimpleName();

        // the remote view fully qualified class name
        String viewClassName = RemoteStatefulSB.class.getName();

        // set up the EJB identifiers for the bean we invoke on
        EJBModuleIdentifier MODULE_IDENTIFIER = new EJBModuleIdentifier(appName, moduleName, distinctName);
        EJBIdentifier EJB_IDENTIFIER = new EJBIdentifier(MODULE_IDENTIFIER, RemoteStatefulSBImpl.class.getSimpleName());

        // Setup the EJBClientContext for this client thread
        EJBClientContext.getContextManager().setThreadDefault(ejbClientContext);

        // setup the AuthenticationConfiguration for this client thread
        AuthenticationConfiguration common = AuthenticationConfiguration.empty()
                .setSaslMechanismSelector(SaslMechanismSelector.fromString("DIGEST-MD5"));
        AuthenticationContext authCtxEmpty = AuthenticationContext.empty();
        AuthenticationConfiguration authCfg = common.useName(username).usePassword(password);
        final AuthenticationContext authCtx = authCtxEmpty.with(MatchRule.ALL, authCfg);
        AuthenticationContext.getContextManager().setThreadDefault(authCtx);


        LOG.trace("{}: Serial {}: Creating SFSB proxy using EJBClient API.", threadName, serial);
        try {
            StatelessEJBLocator<RemoteStatefulSB> statefulEJBLocator = StatelessEJBLocator.create(RemoteStatefulSB.class, EJB_IDENTIFIER, Affinity.NONE);
            session = EJBClient.createSessionProxy(statefulEJBLocator);
            Affinity strongAffinity = EJBClient.getStrongAffinity(session);
            Affinity weakAffinity = EJBClient.getWeakAffinity(session);

            LOG.trace("{}: Serial {}: SFSB proxy created: {} (strong affinity {}, weak affinity {})", threadName, serial, session, strongAffinity, weakAffinity);
        } catch (Exception e) {
            LOG.error("{}: Serial {}: Error during SFSB proxy creation. ", threadName, serial, e);

            //we need to set timestamps, otherwise the corresponding log will have timestamp set to 0
            sampleResult.sampleStart();
            sampleResult.sampleEnd();
            sampleResult.setResponseMessage(String.format("%s: Serial %d: Error during initialContext creation. Caused by: %s", threadName, serial, e.getMessage()));
            sampleResult.setSuccessful(false);
            return false;
        }

        if (invocationTimeout > 0) {
            //EJB Client internal API usage, will work only with EJBClient 4.x
            LOG.trace("{}: Serial {}: Setting the invocation timeout for EJB client proxy to: {} seconds", threadName, serial, invocationTimeout);
            EJBClient.setInvocationTimeout(session, invocationTimeout, TimeUnit.SECONDS);
        }

        return true;
    }

    /**
     * Contains custom validation logic for EJB clustering scenarios. gotSerial parameter represents counter for this bean call.
     * Compares the number against internally stored counter. Values must match, otherwise the sample is considered
     * invalid.
     *
     * @param sampleResult sampleResult instance for storing the validation results
     * @param gotSerial    counter for this bean call
     */
    private void validateResponse(SampleResult sampleResult, int gotSerial) {

        sampleResult.setResponseData(String.valueOf(gotSerial), null); //use platform-default encoding

        if (gotSerial != serial) {
            int syncSerial = gotSerial + 1;
            String errorMessage = String.format("%s: Serial %d: Response serial does not match: Expected %d, received %d", threadName, serial, serial, gotSerial);

            LOG.warn("{}: Serial {}: Syncing next serial to {} from received {}. Expected {}.", threadName, serial, syncSerial, gotSerial, serial);
            serial = syncSerial;

            sampleResult.setResponseMessage(errorMessage);
            sampleResult.setSuccessful(false);
            throw new IllegalStateException(errorMessage);
        } else {
            sampleResult.setResponseMessage("OK: " + serial + "/" + gotSerial);
            sampleResult.setSuccessful(true);
            serial++;
        }
    }

    /**
     * Define default parameters in JMeter GUI test plan.
     */
    @Override
    public Arguments getDefaultParameters() {
        Arguments defaultParameters = new Arguments();
        defaultParameters.addArgument(HOST, "${__P(" + HOST + ",localhost)}");
        defaultParameters.addArgument(PORT, "${__P(" + PORT + ",8080)}");

        defaultParameters.addArgument(USERNAME, "${__P(" + USERNAME + ",joe)}");
        defaultParameters.addArgument(PASSWORD, "${__P(" + PASSWORD + ",secret-Passw0rd)}");

        return defaultParameters;
    }

    /**
     * Prepare data.
     */
    @Override
    public void setupTest(JavaSamplerContext context) {

        super.setupTest(context);

        threadName = context.getJMeterContext().getThread().getThreadName();

        username = context.getJMeterProperties().getProperty(USERNAME); //Fix for remote with remote jmeter clients: host parameter is not propagated when formed by multiples IPs separated by commas
        if (username == null) {
            username = context.getParameter(USERNAME);
        }
        password = context.getJMeterProperties().getProperty(PASSWORD);
        if (password == null) {
            password = context.getParameter(PASSWORD);
        }
        LOG.trace("{}: Setting the credentials for secured connection - username: {} password: {}", threadName, username, password);

        // define urlOfHttpRemotingConnector - we expect a comma-delimited list of 1..n hosts in HOST property and
        // one port (same port for each host) or a comma-delimited list of 1..n ports in PORT property
        hosts = context.getJMeterProperties().getProperty(HOST);
        if (hosts == null) {
            hosts = context.getParameter(HOST);
        }
        ports = context.getJMeterProperties().getProperty(PORT);
        if (ports == null) {
            ports = context.getParameter(PORT);
        }
        String msg1 = String.format(
                "username: %s password: %s hosts: %s ports: %s",
                username, password, hosts, ports
        );
        if (first) LOG.info(msg1);

        try {
            LOG.error("Building EJBClientContext");
            EJBClientContext.Builder builder = new EJBClientContext.Builder();

            final ClassLoader classloader = NativeClusteringEJBRequestSampler.class.getClassLoader();
            // add in transport proviers found on the classpath (e.g. remote, http)
            final ServiceLoader<EJBTransportProvider> serviceLoader = ServiceLoader.load(EJBTransportProvider.class, classloader);
            Iterator<EJBTransportProvider> iterator = serviceLoader.iterator();
            LOG.error("Processing transport providers:");
            for (; ; )
                try {
                    if (!iterator.hasNext()) break;
                    final EJBTransportProvider transportProvider = iterator.next();
                    builder.addTransportProvider(transportProvider);
                    LOG.error("Added transport provider: {}", transportProvider.getClass().getName());
                } catch (ServiceConfigurationError ignored) {
                    LOG.error("Failed to load service", ignored);
                }

            // add in connections to the hosts defined by HOST:PORT pairs with remote+http protocol
            LOG.error("Processing configured connections:");
            for (String uriString : getMiscHelpers().getUrlOfHttpRemotingConnector(hosts, ports, threadName).split(",")) {
                final EJBClientConnection.Builder connBuilder = new EJBClientConnection.Builder();
                // URISyntaxException
                URI uri = null;
                try {
                    uri = new URI(uriString);
                    connBuilder.setDestination(uri);
                    LOG.error("Adding configured connection: {}", uri);
                    builder.addClientConnection(connBuilder.build());
                } catch (URISyntaxException e) {
                    LOG.info("Unable to convert URI {}, skipping", uriString);
                }
            }
            ejbClientContext = builder.build();

            if (first) LOG.info(ejbClientContext.toString());
        } catch (Exception err) {
            LOG.error(msg1, err);
            throw err;
        }
    }

    /**
     * Close the EJB client context.
     */
    @Override
    public void teardownTest(JavaSamplerContext context) {
        super.teardownTest(context);

        // close the proxy we created somehow to free up respources
        // session.close();
    }
}
