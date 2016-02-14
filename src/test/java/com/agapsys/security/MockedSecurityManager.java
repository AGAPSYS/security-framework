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

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 *
 * @author Leandro Oliveira (leandro@agapsys.com)
 */
public class MockedSecurityManager extends com.agapsys.security.SecurityManager {	
	private final Set<String> availableRoles = new LinkedHashSet<>();
	
	public void setAvailableRoles(String...roles) {
		availableRoles.clear();
		
		for (int i = 0; i < roles.length; i++) {
			String role = roles[i];
			if (role == null || role.trim().isEmpty())
				throw new IllegalArgumentException("Null/Empty role at index " + i);
			
			if (!availableRoles.add(role))
				throw new IllegalArgumentException("Duplicate definition of " + role);
		}
	}
	
	public void clearRoles() {
		availableRoles.clear();
	}
	
	@Override
	public boolean isAllowed(String[] requiredRoles) {
		Set<String> requiredRoleSet = new LinkedHashSet<>();
		requiredRoleSet.addAll(Arrays.asList(requiredRoles));
		return availableRoles.containsAll(requiredRoleSet);
	}
}
