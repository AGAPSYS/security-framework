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
import com.agapsys.security.RoleBasedObject;
import com.agapsys.security.RoleRepository;
import java.util.LinkedHashSet;
import java.util.Set;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class UserTest {
	private static class SimpleUser extends RoleBasedObject {

		public SimpleUser() {
		}

		public SimpleUser(Role... defaultRoles) {
			super(defaultRoles);
		}

		public SimpleUser(String... defaultRoles) {
			super(defaultRoles);
		}
	
	}
	
	private RoleRepository roles = RoleRepository.getSingletonInstance();
	
	@Before
	public void before() {
		roles.clear();
	}
	
	@Test
	public void testRoleInstancesInConstructor() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		Set<Role> roleSet = new LinkedHashSet<>();
		roleSet.add(test1);
		roleSet.add(test2);
		roleSet.add(test3);
		
		SimpleUser user = new SimpleUser(test1, test2, test3);
		assertEquals(user.getRoles(), roleSet);
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void testNullRoleInstanceVarArgsInConstructor() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser(test1, null, test3);
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void testNullRoleInstanceInConstructor() {
		SimpleUser user = new SimpleUser((Role)null);
	}
	
	
	@Test
	public void testRoleNamesInConstructor() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		Set<Role> roleSet = new LinkedHashSet<>();
		roleSet.add(test1);
		roleSet.add(test2);
		roleSet.add(test3);
		
		SimpleUser user = new SimpleUser("TEST_1", "TEST_2", "TEST_3");
		assertEquals(user.getRoles(), roleSet);
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void testNullRoleNameVarArgsInConstructor() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser("TEST_1", null, "TEST_3");
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void testNullRoleNameInConstructor() {
		SimpleUser user = new SimpleUser((String)null);
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void testAddDupplicateRoleInstance() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser();
		user.addRole(test1);
		user.addRole(test1);
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void testAddDupplicateRoleName() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser();
		user.addRole("TEST_2");
		user.addRole("TEST_2");
	}
	
	@Test
	public void testRemoveRoleName() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser("TEST_1", "TEST_2", "TEST_3");
		user.removeRole("TEST_2");
		user.removeRole("TEST_3");
		
		Set<Role> expected = new LinkedHashSet<>();
		expected.add(test1);
		
		assertEquals(user.getRoles(), expected);
	}
	
	@Test
	public void testRemoveRoleInstance() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser(test1, test2, test3);
		user.removeRole(test2);
		
		Set<Role> expected = new LinkedHashSet<>();
		expected.add(test1);
		expected.add(test3);
		
		assertEquals(user.getRoles(), expected);
	}
	
	@Test
	public void testClearRoles() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser(test1, test2, test3);
		user.clearRoles();
		
		Set<Role> expected = new LinkedHashSet<>();
		
		assertEquals(user.getRoles(), expected);
	}
}
