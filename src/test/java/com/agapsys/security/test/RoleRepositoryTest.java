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

import com.agapsys.security.Role;
import com.agapsys.security.RoleRepository;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class RoleRepositoryTest {
	private static final RoleRepository ROLES = RoleRepository.getSingletonInstance();
	
	@Before
	public void before() {
		ROLES.clear();
	}
	
	@Test
	public void testAddSingleRole() {
		final String testRole = "test";
		
		assertNull(ROLES.get(testRole));
		
		Role role = ROLES.createRole(testRole);
		
		assertEquals(role, ROLES.get(testRole));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testAddDupplicateRole() {
		ROLES.createRole("TEST");
		ROLES.createRole("TEST");
	}
	
	@Test
	public void testRemoveRole() {
		Role role = ROLES.createRole("TEST");
		assertEquals(role, ROLES.get("TEST"));
		
		ROLES.remove("TEST");
		assertNull(ROLES.get("TEST"));
	}
	
	@Test
	public void testClear() {
		Role role1 = ROLES.createRole("TEST1");
		Role role2 = ROLES.createRole("TEST2");
		
		assertEquals(role1, ROLES.get("TEST1"));
		assertEquals(role2, ROLES.get("TEST2"));
		
		ROLES.clear();
		
		assertNull(ROLES.get("TEST1"));
		assertNull(ROLES.get("TEST2"));
	}
	
}
