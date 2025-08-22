<template>
	<div class="card">
		<h2>Account</h2>
		<div style="display:flex; gap:16px;">
			<form @submit.prevent="login">
				<h3>Login</h3>
				<input v-model="loginEmail" placeholder="Email"/>
				<input v-model="loginPassword" placeholder="Password" type="password"/>
				<button type="submit">Login</button>
			</form>
			<form @submit.prevent="register">
				<h3>Register</h3>
				<input v-model="regEmail" placeholder="Email"/>
				<input v-model="regPassword" placeholder="Password" type="password"/>
				<button type="submit">Create</button>
			</form>
		</div>
		<p v-if="msg" style="margin-top:8px;">{{ msg }}</p>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const loginEmail = ref('');
const loginPassword = ref('');
const regEmail = ref('');
const regPassword = ref('');
const msg = ref('');
function login(){ msg.value = `Logged in as ${loginEmail.value}`; }
function register(){ msg.value = `Created ${regEmail.value}`; }
</script>