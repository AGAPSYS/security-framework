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
import com.agapsys.security.RoleBasedObject;
import com.agapsys.security.RoleRepository;
import java.util.LinkedHashSet;
import java.util.Set;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class UserTest {
	// CLASS SCOPE =============================================================
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
	// =========================================================================
	
	// INSTANCE SCOPE ==========================================================
	private RoleRepository roles = RoleRepository.getSingletonInstance();
	
	@Before
	public void before() {
		roles.clear();
	}
	
	@Test
	public void passingRolesInConstructor() {
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
	public void passingNullInRoleVarArgsConstructor() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser(test1, null, test3);
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void passingNullInRoleVarArgsConstructor2() {
		SimpleUser user = new SimpleUser((Role)null);
	}
	
	
	@Test
	public void passingRoleNamesInConstructor() {
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
	public void passingNullRoleNameInConstructor() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser("TEST_1", null, "TEST_3");
	}
	
	@Test (expected = IllegalArgumentException.class)
	public void passingNullRoleNameInConstructor2() {
		SimpleUser user = new SimpleUser((String)null);
	}
	
	
	@Test (expected = DuplicateException.class)
	public void addDirectDuplicateRole() {
		Role test1 = roles.createRole("TEST_1");
		
		SimpleUser user = new SimpleUser();
		user.addRole(test1);
		user.addRole(test1);
	}
	
	@Test (expected = DuplicateException.class)
	public void addDirectDuplicateRoleName() {
		roles.createRole("TEST_1");
		
		SimpleUser user = new SimpleUser();
		user.addRole("TEST_1");
		user.addRole("TEST_1");
	}
	
	@Test (expected = DuplicateException.class)
	public void addRecursiveDuplicateRole() {
		Role rootRole = roles.createRole("ROOT");
		Role childRole = roles.createRole("CHILD");
		
		rootRole.addChild(childRole);
		
		SimpleUser user= new SimpleUser();
		user.addRole(rootRole);
		user.addRole(childRole); // <-- childRole is child of rootRole
	}
	
	@Test (expected = DuplicateException.class)
	public void addRecursiveDuplicateRoleName() {
		Role rootRole = roles.createRole("ROOT");
		Role childRole = roles.createRole("CHILD");
		
		rootRole.addChild(childRole);
		
		SimpleUser user = new SimpleUser();
		user.addRole("ROOT");
		user.addRole("CHILD"); // <-- childRole is child of rootRole
	}
	
	@Test
	public void removeRoleByName() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser("TEST_1", "TEST_2", "TEST_3");
		user.removeRole("TEST_2");
		user.removeRole("TEST_3");
		
		Set<Role> expected = new LinkedHashSet<>();
		expected.add(test1);
		
		assertEquals(expected, user.getRoles());
	}
	
	@Test
	public void removeRoleByInstance() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser(test1, test2, test3);
		user.removeRole(test2);
		
		Set<Role> expected = new LinkedHashSet<>();
		expected.add(test1);
		expected.add(test3);
		
		assertEquals(expected, user.getRoles());
	}
	
	@Test
	public void clearRoles() {
		Role test1 = roles.createRole("TEST_1");
		Role test2 = roles.createRole("TEST_2");
		Role test3 = roles.createRole("TEST_3");
		
		SimpleUser user = new SimpleUser(test1, test2, test3);
		user.clearRoles();
				
		assertTrue(user.getRoles().isEmpty());
	}
}
