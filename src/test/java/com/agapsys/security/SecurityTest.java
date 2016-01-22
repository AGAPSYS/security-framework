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
		Security.init(new MockedSecurityManager(), "com.agapsys.security.ProtectedClass");
	}
	
	private final MockedSecurityManager securityManager = (MockedSecurityManager) Security.getSecurityManager();
	
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
		ProtectedClass protectedClass = new ProtectedClass();
		protectedClass.unprotected();
		protectedClass.unprotectedWithAnnotation();
		ProtectedClass.staticUnprotected();
		ProtectedClass.staticUnprotectedWithAnnotation();
	}
	
	@Test(expected = NotAllowedException.class)
	public void staticFullyProtectedWithArgs() {
		securityManager.setAvailableRoles("ROLE1", "ROLE2");
		ProtectedClass.staticFullyProtectedWithArgs("hello");
		
		securityManager.clearRoles();
		ProtectedClass.staticFullyProtectedWithArgs("hello");
	}
}
