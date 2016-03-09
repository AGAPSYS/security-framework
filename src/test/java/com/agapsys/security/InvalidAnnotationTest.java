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

import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author Leandro Oliveira (leandro@agapsys.com)
 */
public class InvalidAnnotationTest {
	private static class InnerClass {
		@Secured
		@Unsecured
		public void invalid() {	}	
	}
	
	private final MockedSecurityManager securityManager = (MockedSecurityManager) Security.getSecurityManager();
	
	@Test
	public void testInvalidAnnotations() {
		RuntimeException error = null;
		
		try {
			MockedSecurity.init(new MockedSecurityManager(),
				"com.agapsys.security.InvalidAnnotationTest$InnerClass"
			);
		} catch (RuntimeException ex) {
			error = ex;
		}
		
		Assert.assertNotNull(error);
		Assert.assertEquals("Method 'com.agapsys.security.InvalidAnnotationTest$InnerClass.invalid()' has both 'com.agapsys.security.Secured' and 'com.agapsys.security.Unsecured' annotations", error.getMessage());
	}
}
