/*
 * Copyright (C) 2005-2020 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */
package org.alfresco.encryption;

import java.util.HashSet;
import java.util.Set;
import org.alfresco.error.AlfrescoRuntimeException;
import org.junit.Assert;
import org.junit.Test;

public class AlfrescoKeyStoreTest
{
    @Test
    public void testSysPropsConfig()
    {
        String keyStoreId = "testSysPropsConfig-keystore";
        String alias1 = "mykey1";
        String alias2 = "mykey2";

        KeyStoreParameters keyStoreParameters = new KeyStoreParameters();
        keyStoreParameters.setId(keyStoreId);
        keyStoreParameters.setName("testSysPropsConfig");
        keyStoreParameters.setType("JCEKS");
        keyStoreParameters.setProvider("SunJCE");
        keyStoreParameters.setLocation("classpath:keystore-tests/ks-test-2.jks");

        System.setProperty(keyStoreId + "." + "password", "ksPwd2");
        System.setProperty(keyStoreId + "." + "aliases", alias1 + "," + alias2);
        System.setProperty(keyStoreId + "." + alias1 + "." + "password", "aliasPwd1");
        System.setProperty(keyStoreId + "." + alias2 + "." + "password", "aliasPwd2");

        AlfrescoKeyStore alfrescoKeyStore = new AlfrescoKeyStoreImpl(keyStoreParameters, new SpringKeyResourceLoader());
        Set<String> expectedAliases = new HashSet<>();
        expectedAliases.add(alias1);
        expectedAliases.add(alias2);
        Assert.assertEquals("The aliases are not correct", expectedAliases, alfrescoKeyStore.getKeyAliases());

        Assert.assertNotNull("Failed to retrieve a key from keystore.", alfrescoKeyStore.getKey(alias1));
        Assert.assertNotNull("Failed to retrieve a key from keystore.", alfrescoKeyStore.getKey(alias2));
    }

    @Test(expected = AlfrescoRuntimeException.class)
    public void testSysPropConfigWithoutAliases()
    {
        String keyStoreId = "testSysPropConfigWithoutAliases-keystore";
        String alias1 = "mykey1";

        KeyStoreParameters keyStoreParameters = new KeyStoreParameters();
        keyStoreParameters.setId(keyStoreId);
        keyStoreParameters.setName("testSysPropConfigWithoutAliases");
        keyStoreParameters.setType("JCEKS");
        keyStoreParameters.setProvider("SunJCE");
        keyStoreParameters.setLocation("classpath:keystore-tests/ks-test-1.jks");

        System.setProperty(keyStoreId + "." + "password", "ksPwd2");
        System.setProperty(keyStoreId + "." + alias1 + "." + "password", "aliasPwd1");

        new AlfrescoKeyStoreImpl(keyStoreParameters, new SpringKeyResourceLoader());
    }


    @Test
    public void testMetaDataFileConfig()
    {
        String alias1 = "mykey1";

        KeyStoreParameters keyStoreParameters = new KeyStoreParameters();
        keyStoreParameters.setName("testMetaDataFileConfig");
        keyStoreParameters.setType("JCEKS");
        keyStoreParameters.setProvider("SunJCE");
        keyStoreParameters.setLocation("classpath:keystore-tests/ks-test-1.jks");
        keyStoreParameters.setKeyMetaDataFileLocation("classpath:keystore-tests/ks1-metadata.properties");

        AlfrescoKeyStore alfrescoKeyStore = new AlfrescoKeyStoreImpl(keyStoreParameters, new SpringKeyResourceLoader());
        Set<String> expectedAliases = new HashSet<>();
        expectedAliases.add(alias1);
        Assert.assertEquals("The aliases are not correct", expectedAliases, alfrescoKeyStore.getKeyAliases());

        Assert.assertNotNull("Failed to retrieve a key from keystore.", alfrescoKeyStore.getKey(alias1));
    }

    /**
     * Config via System props should take precedence
     */
    @Test
    public void testConfigBothSystemAndFile()
    {
        String keyStoreId = "testSysPropsConfig-keystore";
        String alias1 = "mykey1";
        String alias2 = "mykey2";

        KeyStoreParameters keyStoreParameters = new KeyStoreParameters();
        keyStoreParameters.setId(keyStoreId);
        keyStoreParameters.setName("testSysPropsConfig");
        keyStoreParameters.setType("JCEKS");
        keyStoreParameters.setProvider("SunJCE");
        keyStoreParameters.setLocation("classpath:keystore-tests/ks-test-2.jks");
        // use metadata file with one key
        keyStoreParameters.setKeyMetaDataFileLocation("classpath:keystore-tests/ks1-metadata.properties");

        System.setProperty(keyStoreId + "." + "password", "ksPwd2");
        System.setProperty(keyStoreId + "." + "aliases", alias1 + "," + alias2);
        System.setProperty(keyStoreId + "." + alias1 + "." + "password", "aliasPwd1");
        System.setProperty(keyStoreId + "." + alias2 + "." + "password", "aliasPwd2");

        AlfrescoKeyStore alfrescoKeyStore = new AlfrescoKeyStoreImpl(keyStoreParameters, new SpringKeyResourceLoader());
        Set<String> expectedAliases = new HashSet<>();
        expectedAliases.add(alias1);
        expectedAliases.add(alias2);
        Assert.assertEquals("The aliases are not correct", expectedAliases, alfrescoKeyStore.getKeyAliases());

        Assert.assertNotNull("Failed to retrieve a key from keystore.", alfrescoKeyStore.getKey(alias1));
        Assert.assertNotNull("Failed to retrieve a key from keystore.", alfrescoKeyStore.getKey(alias2));
    }
}
