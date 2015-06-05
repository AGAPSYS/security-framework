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
import com.agapsys.security.AbstractAction;
import com.agapsys.security.RoleBasedObject;
import com.agapsys.security.RoleRepository;
import com.agapsys.security.User;
import com.agapsys.security.SecurityException;
import org.junit.Test;

public class SecuredActionTest {
	// CLASS SCOPE =============================================================
	private static final RoleRepository ROLES = RoleRepository.getSingletonInstance();
	private static final Role DEFAULT_AUTHENTICATED_ROLE = ROLES.createRole("AUTHENTICATED");
	
	static {	
		ROLES.createRole("ADD");
		ROLES.createRole("REMOVE");
		ROLES.getOrCreate("RW");
		ROLES.getOrCreate("EXECUTE");
		
		ROLES.get("RW").addChild("ADD", "REMOVE");
	}
	
	private static class TestUser extends RoleBasedObject implements User {
		
		public TestUser(String...roles) {
			super(DEFAULT_AUTHENTICATED_ROLE);
			
			addRole(roles);
		}
	}
	
	private static final AbstractAction ACTION_ADD = new AbstractAction("AUTHENTICATED", "ADD") {
		@Override
		protected void run(User user, Object...params) {}
	};
	
	private static final AbstractAction ACTION_REMOVE = new AbstractAction("AUTHENTICATED", "REMOVE") {
		@Override
		protected void run(User user, Object...params) {}
		
	};
	
	private static final AbstractAction ACTION_RW = new AbstractAction("AUTHENTICATED", "RW") {
		@Override
		protected void run(User user, Object...params) {}
		
	};

	private static final AbstractAction ACTION_AUTHENTICATED = new AbstractAction("AUTHENTICATED") {
		@Override
		protected void run(User user, Object...params) {}
		
	};
	
	private static final AbstractAction ACTION_EXECUTE = new AbstractAction("AUTHENTICATED", "EXECUTE") {
		@Override
		protected void run(User user, Object...params) {}
		
	};
	
	private static final AbstractAction ACTION_PUBLIC = new AbstractAction() {
		@Override
		protected void run(User user, Object...params) {}
	};

	private static final TestUser USER_ADD = new TestUser("ADD");
	private static final TestUser USER_REMOVE = new TestUser("REMOVE");
	private static final TestUser USER_RW = new TestUser("RW");
	private static final TestUser USER_EXECUTE = new TestUser("EXECUTE");
	// =========================================================================
	
	// INSTANCE SCOPE ==========================================================	
	@Test
	public void testSecurityOk() throws SecurityException {
		ACTION_PUBLIC.execute(null);
		ACTION_PUBLIC.execute(USER_ADD);

		ACTION_ADD.execute(USER_ADD);
		ACTION_ADD.execute(USER_RW);
		
		ACTION_REMOVE.execute(USER_REMOVE);
		ACTION_REMOVE.execute(USER_RW);
		
		ACTION_RW.execute(USER_RW);
		ACTION_EXECUTE.execute(USER_EXECUTE);
		
		ACTION_AUTHENTICATED.execute(USER_ADD);
		ACTION_AUTHENTICATED.execute(USER_EXECUTE);
		ACTION_AUTHENTICATED.execute(USER_REMOVE);
		ACTION_AUTHENTICATED.execute(USER_RW);
	}

	@Test(expected = SecurityException.class)
	public void testUnauthenticatedUser() throws SecurityException {
		ACTION_AUTHENTICATED.execute(null);
	}
	
	@Test(expected = SecurityException.class)
	public void testInsufficientPrivileges() throws SecurityException {
		ACTION_ADD.execute(USER_REMOVE);
	}
	
	@Test(expected = SecurityException.class)
	public void testInsufficientPrivileges2() throws SecurityException {
		ACTION_RW.execute(USER_REMOVE);
	}
}
