/*
 * Copyright 2016 Agapsys Tecnologia Ltda-ME.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.agapsys.security;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Leandro Oliveira (leandro@agapsys.com)
 */
public class AutoSecurityTest {

	@BeforeClass
	public static void beforeClass() {
		MockedSecurity.init(new MockedSecurityManager());
	}
	
	private final MockedSecurityManager securityManager = (MockedSecurityManager) Security.getSecurityManager();
	
	// private AutoAutoProtectedClass pc; // <-- Uncommenting this will cause javassist.CannotCompileException due to duplicate class definition
	
	@Before
	public void before() {
		securityManager.clearRoles();
	}
	
	@After
	public void after() {
		System.out.println();
	}
	
	@Test
	public void unprotectedTest() {
		AutoSecuredClass autoAutoProtectedClass = new AutoSecuredClass();
		autoAutoProtectedClass.unsecured();
		autoAutoProtectedClass.unsecuredWithAnnotation();
		
		AutoSecuredClass.staticUnsecured();
		AutoSecuredClass.staticUnsecuredWithAnnotation();
	}
	
	@Test
	public void staticMethods() {
		NotAllowedException error;
		
		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			AutoSecuredClass.staticSecuredWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoSecuredClass.staticSecuredWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticProtected OK---------------------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			AutoSecuredClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtected REJECTED --------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoSecuredClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoSecuredClass.staticUnsecuredWithAnnotation();
			securityManager.setAvailableRoles("test");
			AutoSecuredClass.staticUnsecuredWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected OK ------------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoSecuredClass.staticUnsecured();
			securityManager.setAvailableRoles("test");
			AutoSecuredClass.staticUnsecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected OK ---------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			securityManager.setAvailableRoles("ROLE");
			AutoSecuredClass.staticChainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected REJECTED ---------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoSecuredClass.staticChainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
	}
	
	@Test
	public void instanceMethods() {
		NotAllowedException error;
		AutoSecuredClass autoProtectedClass = new AutoSecuredClass();
		
		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			autoProtectedClass.securedWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.securedWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticProtected OK---------------------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			autoProtectedClass.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtected REJECTED --------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.unsecuredWithAnnotation();
			securityManager.setAvailableRoles("test");
			autoProtectedClass.unsecuredWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected OK ------------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.unsecured();
			securityManager.setAvailableRoles("test");
			autoProtectedClass.unsecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected OK ---------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			securityManager.setAvailableRoles("ROLE");
			autoProtectedClass.chainSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected REJECTED ---------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.chainSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
	}
}
