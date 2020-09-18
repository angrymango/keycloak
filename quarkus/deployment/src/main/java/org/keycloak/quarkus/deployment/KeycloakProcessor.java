/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.quarkus.deployment;

import javax.persistence.spi.PersistenceUnitTransactionType;
import java.util.*;

import com.fasterxml.jackson.annotation.JsonProperty;
import freemarker.ext.jython.JythonModel;
import freemarker.ext.jython.JythonWrapper;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.IsDevelopment;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.HotDeploymentWatchedFileBuildItem;
import io.quarkus.deployment.builditem.IndexDependencyBuildItem;
import io.quarkus.deployment.builditem.nativeimage.*;
import io.quarkus.deployment.pkg.steps.NativeBuild;
import io.quarkus.hibernate.orm.deployment.HibernateOrmConfig;
import io.quarkus.resteasy.common.spi.ResteasyDotNames;
import liquibase.parser.ChangeLogParserCofiguration;
import org.hibernate.cfg.AvailableSettings;
import org.hibernate.jpa.boot.spi.PersistenceUnitDescriptor;
import org.jboss.jandex.*;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.common.Profile;
import org.keycloak.config.ConfigProviderFactory;
import org.keycloak.configuration.PropertyMappingInterceptor;
import org.keycloak.connections.jpa.DefaultJpaConnectionProviderFactory;
import org.keycloak.connections.jpa.updater.liquibase.LiquibaseJpaUpdaterProviderFactory;
import org.keycloak.connections.jpa.updater.liquibase.conn.DefaultLiquibaseConnectionProvider;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.KeycloakDeploymentInfo;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.ProviderManager;
import org.keycloak.provider.Spi;
import org.keycloak.provider.quarkus.QuarkusCacheManagerProvider;
import org.keycloak.provider.quarkus.QuarkusRequestFilter;
import org.keycloak.quarkus.KeycloakRecorder;

import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.hibernate.orm.deployment.PersistenceUnitDescriptorBuildItem;
import io.quarkus.vertx.http.deployment.FilterBuildItem;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.storage.openshift.OpenshiftClientStorageProvider;
import org.keycloak.transaction.JBossJtaTransactionManagerLookup;
import org.keycloak.util.Environment;

class KeycloakProcessor {

    private static final Logger logger = Logger.getLogger(KeycloakProcessor.class);
    public static final DotName JSON_PROPERTY = DotName.createSimple(JsonProperty.class.getName());
    public static final DotName ABSTRACT_IDENTITY_PROVIDER_FACTORY = DotName.createSimple(AbstractIdentityProviderFactory.class.getName());

    @BuildStep
    FeatureBuildItem getFeature() {
        return new FeatureBuildItem("keycloak");
    }

    @BuildStep(onlyIf = NativeBuild.class)
    void setup(BuildProducer<IndexDependencyBuildItem> indexDependency) {
        indexDependency.produce(new IndexDependencyBuildItem("org.keycloak", "keycloak-core"));
        indexDependency.produce(new IndexDependencyBuildItem("org.keycloak", "keycloak-server-spi"));
        indexDependency.produce(new IndexDependencyBuildItem("org.keycloak", "keycloak-services"));
    }

    @BuildStep(onlyIf = NativeBuild.class)
    void setup(BuildProducer<ReflectiveClassBuildItem> reflectiveClass,
               BuildProducer<RuntimeInitializedClassBuildItem> runtimeClass,
               CombinedIndexBuildItem combinedIndexBuildItem) {

        runtimeClass.produce(new RuntimeInitializedClassBuildItem(OpenshiftClientStorageProvider.class.getCanonicalName()));
        runtimeClass.produce(new RuntimeInitializedClassBuildItem(JythonWrapper.class.getCanonicalName()));
        runtimeClass.produce(new RuntimeInitializedClassBuildItem(JythonModel.class.getCanonicalName()));
//        runtimeClass.produce(new RuntimeInitializedClassBuildItem(AbstractJBossMarshaller.class.getCanonicalName()));

        Map<Spi, Map<Class<? extends Provider>, Map<String, ProviderFactory>>> factories = loadFactories();
        factories.forEach((k1, v1) -> v1.forEach((k2, v2) -> {
                    reflectiveClass.produce(new ReflectiveClassBuildItem(false, false, k2.getCanonicalName()));
                    v2.forEach((k3, v3) ->
                            reflectiveClass.produce(new ReflectiveClassBuildItem(false, false, v3.getClass().getCanonicalName()))
                    );
                }
        ));

        reflectiveClass.produce(new ReflectiveClassBuildItem(true, false, QuarkusCacheManagerProvider.class.getCanonicalName()));
        reflectiveClass.produce(new ReflectiveClassBuildItem(false, false, ChangeLogParserCofiguration.class.getCanonicalName()));

        IndexView index = combinedIndexBuildItem.getIndex();
        Set<ClassInfo> resourceClasses = new HashSet<>();

        Collection<AnnotationInstance> annotations = new ArrayList<>();
        annotations.addAll(index.getAnnotations(JSON_PROPERTY));
        annotations.addAll(index.getAnnotations(ResteasyDotNames.PATH));

        for (AnnotationInstance deserializeInstance : annotations) {
            AnnotationTarget annotationTarget = deserializeInstance.target();

            switch (annotationTarget.kind()) {
                case CLASS:
                    resourceClasses.add(annotationTarget.asClass());
                    break;
                case METHOD:
                    resourceClasses.add(annotationTarget.asMethod().declaringClass());
                    break;
            }
        }

        for (DotName annotation : ResteasyDotNames.JAXRS_METHOD_ANNOTATIONS) {
            for (AnnotationInstance deserializeInstance : index.getAnnotations(annotation)) {
                AnnotationTarget annotationTarget = deserializeInstance.target();
                resourceClasses.add(annotationTarget.asMethod().declaringClass());
            }
        }

        index.getKnownClasses()
                .stream()
                .map(ClassInfo::name)
                .map(DotName::toString)
                .filter(c -> c.startsWith("org.keycloak.representations") ||
                        c.endsWith("Representation") ||
                        c.endsWith("Bean") ||
                        c.endsWith("Model"))
                .forEach(c -> reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, c)));

        index.getKnownDirectSubclasses(ABSTRACT_IDENTITY_PROVIDER_FACTORY)
                .stream()
                .map(ClassInfo::name)
                .map(DotName::toString)
                .forEach(c -> reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, c)));

        resourceClasses.forEach(ci -> reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, ci.name().toString())));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, AuthorizationEndpointBase.class.getCanonicalName()));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, JWSHeader.class.getCanonicalName()));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, "org.keycloak.services.resources.admin.AdminConsole$WhoAmI"));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, Integer.class.getCanonicalName()));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, Boolean.class.getCanonicalName()));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, false, PropertyMappingInterceptor.class.getCanonicalName()));
    }

    /**
     * <p>Configures the persistence unit for Quarkus.
     *
     * <p>The main reason we have this build step is because we re-use the same persistence unit from {@code keycloak-model-jpa}
     * module, the same used by the Wildfly distribution. The {@code hibernate-orm} extension expects that the dialect is statically
     * set to the persistence unit if there is any from the classpath and we use this method to obtain the dialect from the configuration
     * file so that we can build the application with whatever dialect we want. In addition to the dialect, we should also be
     * allowed to set any additional defaults that we think that makes sense.
     *
     * @param recorder
     * @param config
     * @param descriptors
     */
    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep
    void configureHibernate(KeycloakRecorder recorder, HibernateOrmConfig config, List<PersistenceUnitDescriptorBuildItem> descriptors) {
        PersistenceUnitDescriptor unit = descriptors.get(0).asOutputPersistenceUnitDefinition().getActualHibernateDescriptor();

        unit.getProperties().setProperty(AvailableSettings.DIALECT, config.defaultPersistenceUnit.dialect.dialect.orElse(null));
        unit.getProperties().setProperty(AvailableSettings.JPA_TRANSACTION_TYPE, PersistenceUnitTransactionType.JTA.name());
        unit.getProperties().setProperty(AvailableSettings.QUERY_STARTUP_CHECKING, Boolean.FALSE.toString());
    }

    /**
     * <p>Load the built-in provider factories during build time so we don't spend time looking up them at runtime. By loading
     * providers at this stage we are also able to perform a more dynamic configuration based on the default providers.
     *
     * <p>User-defined providers are going to be loaded at startup</p>
     *
     * @param recorder
     */
    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep
    void configureProviders(KeycloakRecorder recorder) {
        Profile.setInstance(recorder.createProfile());
        Map<Spi, Map<Class<? extends Provider>, Map<String, Class<? extends ProviderFactory>>>> factories = new HashMap<>();
        Map<Class<? extends Provider>, String> defaultProviders = new HashMap<>();

        for (Map.Entry<Spi, Map<Class<? extends Provider>, Map<String, ProviderFactory>>> entry : loadFactories()
                .entrySet()) {
            checkProviders(entry.getKey(), entry.getValue(), defaultProviders);

            for (Map.Entry<Class<? extends Provider>, Map<String, ProviderFactory>> value : entry.getValue().entrySet()) {
                for (ProviderFactory factory : value.getValue().values()) {
                    factories.computeIfAbsent(entry.getKey(),
                            key -> new HashMap<>())
                            .computeIfAbsent(entry.getKey().getProviderClass(), aClass -> new HashMap<>()).put(factory.getId(), factory.getClass());
                }
            }
        }

        recorder.configSessionFactory(factories, defaultProviders, Environment.isRebuild());
    }

    /**
     * <p>Make the build time configuration available at runtime so that the server can run without having to specify some of
     * the properties again.
     *
     * <p>This build step also adds a static call to {@link org.keycloak.cli.ShowConfigCommand#run(Map)} via the recorder
     * so that the configuration can be shown when requested.
     *
     * @param recorder the recorder
     */
    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep
    void setBuildTimeProperties(KeycloakRecorder recorder) {
        Map<String, String> properties = new HashMap<>();

        for (String name : KeycloakRecorder.getConfig().getPropertyNames()) {
            if (isRuntimeProperty(name)) {
                continue;
            }

            Optional<String> value = KeycloakRecorder.getConfig().getOptionalValue(name, String.class);

            if (value.isPresent()) {
                properties.put(name, value.get());
            }
        }

        recorder.setBuildTimeProperties(properties, Environment.isRebuild());

        recorder.showConfig();
    }

    private boolean isRuntimeProperty(String name) {
        // these properties are ignored from the build time properties as they are runtime-specific
        return "kc.home.dir".equals(name) || "kc.config.args".equals(name);
    }

    @BuildStep
    void initializeRouter(BuildProducer<FilterBuildItem> routes) {
        routes.produce(new FilterBuildItem(new QuarkusRequestFilter(), FilterBuildItem.AUTHORIZATION - 10));
    }

    @BuildStep(onlyIf = IsDevelopment.class)
    void configureDevMode(BuildProducer<HotDeploymentWatchedFileBuildItem> hotFiles) {
        hotFiles.produce(new HotDeploymentWatchedFileBuildItem("META-INF/keycloak.properties"));
    }

    private Map<Spi, Map<Class<? extends Provider>, Map<String, ProviderFactory>>> loadFactories() {
        loadConfig();
        ProviderManager pm = new ProviderManager(KeycloakDeploymentInfo.create().services(), new BuildClassLoader());
        Map<Spi, Map<Class<? extends Provider>, Map<String, ProviderFactory>>> factories = new HashMap<>();

        for (Spi spi : pm.loadSpis()) {
            Map<Class<? extends Provider>, Map<String, ProviderFactory>> providers = new HashMap<>();

            for (ProviderFactory factory : pm.load(spi)) {
                if (Arrays.asList(
                        JBossJtaTransactionManagerLookup.class,
                        DefaultJpaConnectionProviderFactory.class,
                        DefaultLiquibaseConnectionProvider.class,
                        LiquibaseJpaUpdaterProviderFactory.class).contains(factory.getClass())) {
                    continue;
                }

                Config.Scope scope = Config.scope(spi.getName(), factory.getId());

                if (isEnabled(factory, scope)) {
                    if (spi.isInternal() && !isInternal(factory)) {
                        ServicesLogger.LOGGER.spiMayChange(factory.getId(), factory.getClass().getName(), spi.getName());
                    }

                    providers.computeIfAbsent(spi.getProviderClass(), aClass -> new HashMap<>()).put(factory.getId(),
                            factory);
                } else {
                    logger.debugv("SPI {0} provider {1} disabled", spi.getName(), factory.getId());
                }
            }

            factories.put(spi, providers);
        }

        return factories;
    }

    private boolean isEnabled(ProviderFactory factory, Config.Scope scope) {
        if (!scope.getBoolean("enabled", true)) {
            return false;
        }
        if (factory instanceof EnvironmentDependentProviderFactory) {
            return ((EnvironmentDependentProviderFactory) factory).isSupported();
        }
        return true;
    }

    private boolean isInternal(ProviderFactory<?> factory) {
        String packageName = factory.getClass().getPackage().getName();
        return packageName.startsWith("org.keycloak") && !packageName.startsWith("org.keycloak.examples");
    }

    private void checkProviders(Spi spi,
                                Map<Class<? extends Provider>, Map<String, ProviderFactory>> factoriesMap,
                                Map<Class<? extends Provider>, String> defaultProviders) {
        String defaultProvider = Config.getProvider(spi.getName());

        if (defaultProvider != null) {
            Map<String, ProviderFactory> map = factoriesMap.get(spi.getProviderClass());
            if (map == null || map.get(defaultProvider) == null) {
                throw new RuntimeException("Failed to find provider " + defaultProvider + " for " + spi.getName());
            }
        } else {
            Map<String, ProviderFactory> factories = factoriesMap.get(spi.getProviderClass());
            if (factories != null && factories.size() == 1) {
                defaultProvider = factories.values().iterator().next().getId();
            }

            if (factories != null) {
                if (defaultProvider == null) {
                    Optional<ProviderFactory> highestPriority = factories.values().stream()
                            .max(Comparator.comparing(ProviderFactory::order));
                    if (highestPriority.isPresent() && highestPriority.get().order() > 0) {
                        defaultProvider = highestPriority.get().getId();
                    }
                }
            }

            if (defaultProvider == null && (factories == null || factories.containsKey("default"))) {
                defaultProvider = "default";
            }
        }

        if (defaultProvider != null) {
            defaultProviders.put(spi.getProviderClass(), defaultProvider);
        } else {
            logger.debugv("No default provider for {0}", spi.getName());
        }
    }

    protected void loadConfig() {
        ServiceLoader<ConfigProviderFactory> loader = ServiceLoader.load(ConfigProviderFactory.class, KeycloakApplication.class.getClassLoader());

        try {
            ConfigProviderFactory factory = loader.iterator().next();
            logger.debugv("ConfigProvider: {0}", factory.getClass().getName());
            Config.init(factory.create().orElseThrow(() -> new RuntimeException("Failed to load Keycloak configuration")));
        } catch (NoSuchElementException e) {
            throw new RuntimeException("No valid ConfigProvider found");
        }
    }
}
