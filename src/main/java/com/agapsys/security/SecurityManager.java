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

public abstract class SecurityManager {
	/** 
	 * Checks if execution is allowed for given roles
	 * @param requiredRoles required roles for execution
	 * @return a boolean indicating if execution is allowed.
	 */
	public abstract boolean isAllowed(String[] requiredRoles);
	
	/** 
	 * Called if an execution is not allowed.
	 * @throws NotAllowedException if an execution is not allowed.
	 */
	public void onNotAllowed() throws NotAllowedException {
		throw new NotAllowedException();
	}
}
