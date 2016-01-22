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
public class MockedSecurityManager implements com.agapsys.security.SecurityManager {
	// CLASS SCOPE =============================================================
	private static class NonEmptyStringSet extends LinkedHashSet<String> {

		@Override
		public boolean add(String e) {
			if (e == null || e.trim().isEmpty())
				throw new IllegalArgumentException("Cannot add neither null nor an empty string");
			
			return super.add(e);
		}
	}
	// =========================================================================
	
	private final Set<String> availableRoles = new NonEmptyStringSet();
	
	public void setAvailableRoles(String...roles) {
		availableRoles.clear();
		availableRoles.addAll(Arrays.asList(roles));
	}
	
	public void clearRoles() {
		availableRoles.clear();
	}
	
	@Override
	public boolean isAllowed(String[] requiredRoles) {
		Set<String> requiredRoleSet = new NonEmptyStringSet();
		requiredRoleSet.addAll(Arrays.asList(requiredRoles));
		return availableRoles.containsAll(requiredRoleSet);
	}

	@Override
	public void onNotAllowed() {
		throw new NotAllowedException();
	}
	
}
