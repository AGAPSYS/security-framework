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
	
	// private SecuredClass pc; // <-- Uncommenting this will cause javassist.CannotCompileException due to duplicate class definition
	
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
		protectedClass.implicitSecured();
		protectedClass.secured2();
		SecuredClass.staticImplicitSecured();
		SecuredClass.staticSecured2();
	}
	
	@Test
	public void staticMethods() {
		NotAllowedException error;
		
		// staticSecuredWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			SecuredClass.staticSecuredWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticSecuredWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			SecuredClass.staticSecuredWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticSecured OK---------------------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			SecuredClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticSecured REJECTED --------------------------------------------
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
			SecuredClass.staticSecured2();
			securityManager.setAvailableRoles("CLASS_ROLE", "test");
			SecuredClass.staticSecured2();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotectedWithAnnotation REJECTED ----------------------------
		error = null;
		securityManager.clearRoles();

		try {
			SecuredClass.staticSecured2();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticUnprotected OK ------------------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");
		
		try {
			SecuredClass.staticImplicitSecured();
			securityManager.setAvailableRoles("CLASS_ROLE", "test");
			SecuredClass.staticImplicitSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected REJECTED ------------------------------------------
		error = null;
		securityManager.clearRoles();
		
		try {
			SecuredClass.staticImplicitSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticChainSecured OK ---------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			SecuredClass.staticChainSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainSecured REJECTED ---------------------------------------
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
		
		// staticSecuredWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			protectedClass.securedWithArgs("test");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticSecuredWithArgs REJECTED ------------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			protectedClass.securedWithArgs("hello");
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticSecured OK---------------------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			protectedClass.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticSecured REJECTED --------------------------------------------
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
			protectedClass.secured2();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		
		
		
		
		// staticUnprotectedWithAnnotation OK ----------------------------------
		error = null;
		securityManager.setAvailableRoles("CLASS_ROLE");

		try {
			protectedClass.secured2();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticUnprotected REJECTED ------------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			protectedClass.implicitSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		// staticChainSecured OK ---------------------------------------------
		error = null;

		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE");
			protectedClass.chainSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNull(error);
		// staticChainSecured REJECTED ---------------------------------------
		error = null;
		securityManager.clearRoles();

		try {
			protectedClass.chainSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
	}
	
	@Test
	public void innerStaticClassTest() {
		NotAllowedException error;

		// staticSecuredWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE"); // <-- CLASS_ROLE is required since println static method belongs to outter class (which is secured)
			SecuredClass.InnerStaticClass.staticSecured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		
		Assert.assertNull(error);
		// staticSecuredWithArgs REJECTED ------------------------------
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
		
		// staticSecuredWithArgs OK ------------------------------------
		error = null;
		
		try {
			securityManager.setAvailableRoles("CLASS_ROLE", "ROLE"); // <-- CLASS_ROLE is required since println static method belongs to outter class (which is secured)
			innerObj.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		
		Assert.assertNull(error);
		// staticSecuredWithArgs REJECTED ------------------------------
		error = null;
		
		try {
			securityManager.clearRoles();
			innerObj.secured();
		} catch (NotAllowedException ex) {
			error = ex;
		}
		
		
		Assert.assertNotNull(error);
	}
	
	@Test
	public void unsecuredMethodTest() {
		NotAllowedException error = null;
		SecuredClass securedObj = new SecuredClass();
		
		try {
			securedObj.unsecured();
		} catch (NotAllowedException t) {
			error = t;
		}
		
		Assert.assertNull(error);
	}
}
