/*
 * Copyright 2015 Agapsys Tecnologia Ltda-ME.
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

package com.agapsys.security.test;

import com.agapsys.security.DuplicateException;
import com.agapsys.security.Role;
import com.agapsys.security.RoleRepository;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class RoleRepositoryTest {
	private static final RoleRepository roles = RoleRepository.getSingletonInstance();

	@Before
	public void before() {
		roles.clear();
	}
	
	@After
	public void after() {
		roles.clear();
	}
	
	@Test
	public void addSingleRole() {
		final String testRole = "test";
		
		assertNull(roles.get(testRole));
		
		Role role = roles.createRole(testRole);
		
		assertEquals(role, roles.get(testRole));
	}
	
	@Test(expected = DuplicateException.class)
	public void addDuplicateRole() {
		roles.createRole("TEST");
		roles.createRole("TEST");
	}
	
	@Test
	public void removeRole() {
		Role role = roles.createRole("TEST");
		assertEquals(role, roles.get("TEST"));
		
		roles.remove("TEST");
		assertNull(roles.get("TEST"));
	}
	
	@Test
	public void clearRoles() {
		Role role1 = roles.createRole("TEST1");
		Role role2 = roles.createRole("TEST2");
		
		assertEquals(role1, roles.get("TEST1"));
		assertEquals(role2, roles.get("TEST2"));
		
		roles.clear();
		
		assertNull(roles.get("TEST1"));
		assertNull(roles.get("TEST2"));
	}
}
