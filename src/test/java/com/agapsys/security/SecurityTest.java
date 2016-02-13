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

import com.agapsys.security.SecuredClass.InnerClass;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Leandro Oliveira (leandro@agapsys.com)
 */
public class SecurityTest {

	@BeforeClass
	public static void beforeClass() {
		MockedSecurity.init(new MockedSecurityManager(),
			"com.agapsys.security.SecuredClass",
			"com.agapsys.security.SecuredClass$InnerStaticClass",
			"com.agapsys.security.SecuredClass$InnerClass"
		);
	}
	
	private final MockedSecurityManager securityManager = (MockedSecurityManager) Security.getSecurityManager();
	
	// private ProtectedClass pc; // <-- Uncommenting this will cause javassist.CannotCompileException due to duplicate class definition
	
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
		securityManager.setAvailableRoles("CLASS_ROLE");

		SecuredClass protectedClass = new SecuredClass();
		protectedClass.unsecured();
		protectedClass.unsecuredWithAnnotation();
		SecuredClass.staticUnsecured();
		SecuredClass.staticUnsecuredWithAnnotation();
	}
	
	@Test
	public void staticMethods() {
		NotAllowedException error;
		
		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			SecuredClass.staticSecuredWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			SecuredClass.staticSecuredWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticProtected OK---------------------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			SecuredClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtected REJECTED --------------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			SecuredClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			SecuredClass.staticUnsecuredWithAnnotation();
			securityManager.setAvailableRoles("CLASS_ROLE", "test");
			SecuredClass.staticUnsecuredWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotectedWithAnnotation REJECTED ----------------------------
		error = null;
		securityManager.clearRoles();

		try {
			SecuredClass.staticUnsecuredWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotected OK ------------------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");
		
		try {
			SecuredClass.staticUnsecured();
			securityManager.setAvailableRoles("CLASS_ROLE", "test");
			SecuredClass.staticUnsecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected REJECTED ------------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			SecuredClass.staticUnsecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticChainProtected OK ---------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			SecuredClass.staticChainSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected REJECTED ---------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			SecuredClass.staticChainSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
	}
	
	@Test
	public void instanceMethods() {
		NotAllowedException error;
		SecuredClass protectedClass = new SecuredClass();
		
		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			protectedClass.securedWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			protectedClass.securedWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticProtected OK---------------------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			protectedClass.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticProtected REJECTED --------------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			protectedClass.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			protectedClass.unsecuredWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		
		
		
		
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			protectedClass.unsecuredWithAnnotation();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected REJECTED ------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			protectedClass.unsecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticChainProtected OK ---------------------------------------------
		error = null;

		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			protectedClass.chainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainProtected REJECTED ---------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			protectedClass.chainProtected();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
	}
	
	@Test
	public void innerStaticClassTest() {
		NotAllowedException error;

		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE"); // <-- CLASS_ROLE is required since println static method belongs to outter class (which is secured)
			SecuredClass.InnerStaticClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------
		error = null;
		
		try {
			securityManager.clearRoles();
			SecuredClass.InnerStaticClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		
		Assert.assertNotNull(error);
	}
	
	@Test
	public void innerClassTest() {
		NotAllowedException error;
		SecuredClass securedObj = new SecuredClass();
		InnerClass innerObj = securedObj.new InnerClass();
		
		// staticProtectedWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE"); // <-- CLASS_ROLE is required since println static method belongs to outter class (which is secured)
			innerObj.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		
		Assert.assertNull(error);
		// staticProtectedWithArgs REJECTED ------------------------------
		error = null;
		
		try {
			securityManager.clearRoles();
			innerObj.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		
		Assert.assertNotNull(error);
	}
}
