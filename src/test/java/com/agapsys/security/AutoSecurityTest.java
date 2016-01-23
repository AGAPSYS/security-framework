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
		MockedSecurity.allowMultipleInitialization();
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
		AutoProtectedClass autoAutoProtectedClass = new AutoProtectedClass();
		autoAutoProtectedClass.unprotected();
		autoAutoProtectedClass.unprotectedWithAnnotation();
		
		AutoProtectedClass.staticUnprotected();
		AutoProtectedClass.staticUnprotectedWithAnnotation();
	}
	
	@Test
	public void staticMethods() {
		NotAllowedException error;
		
		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			AutoProtectedClass.staticProtectedWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoProtectedClass.staticProtectedWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticProtected OK---------------------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			AutoProtectedClass.staticProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtected REJECTED --------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoProtectedClass.staticProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoProtectedClass.staticUnprotectedWithAnnotation();
			securityManager.setAvailableRoles("test");
			AutoProtectedClass.staticUnprotectedWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected OK ------------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoProtectedClass.staticUnprotected();
			securityManager.setAvailableRoles("test");
			AutoProtectedClass.staticUnprotected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected OK ---------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			securityManager.setAvailableRoles("ROLE");
			AutoProtectedClass.staticChainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected REJECTED ---------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			AutoProtectedClass.staticChainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
	}
	
	@Test
	public void instanceMethods() {
		NotAllowedException error;
		AutoProtectedClass autoProtectedClass = new AutoProtectedClass();
		
		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			autoProtectedClass.protectedWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.protectedWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticProtected OK---------------------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			securityManager.setAvailableRoles("ROLE");
			autoProtectedClass.protectedMethod();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtected REJECTED --------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.protectedMethod();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.unprotectedWithAnnotation();
			securityManager.setAvailableRoles("test");
			autoProtectedClass.unprotectedWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected OK ------------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.unprotected();
			securityManager.setAvailableRoles("test");
			autoProtectedClass.unprotected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected OK ---------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			securityManager.setAvailableRoles("ROLE");
			autoProtectedClass.chainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected REJECTED ---------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			autoProtectedClass.chainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
	}
}
