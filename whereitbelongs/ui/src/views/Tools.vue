<template>
	<div class="card">
		<h2>Tools</h2>
		<div style="display:flex; gap:8px;">
			<input v-model="shredPath" placeholder="File to shred" />
			<button @click="shred">Shred</button>
		</div>
		<div style="display:flex; gap:8px; margin-top:8px;">
			<input v-model="vaultItem" placeholder="Vault item" />
			<button @click="addVault">Add to Vault</button>
		</div>
		<ul>
			<li v-for="v in vault" :key="v">🔒 {{ v }}</li>
		</ul>
		<div style="margin-top:12px; display:flex; gap:8px; align-items:center;">
			<label><input type="checkbox" v-model="vpn"/> Secure VPN</label>
			<button @click="refreshIntel">Refresh Dark Web RAT Intelligence</button>
		</div>
		<pre style="max-height:160px; overflow:auto;">{{ intel.join('\n') }}</pre>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const shredPath = ref('');
const vaultItem = ref('');
const vault = ref<string[]>([]);
const vpn = ref(false);
const intel = ref<string[]>([]);
function shred(){ if (shredPath.value) { shredPath.value=''; } }
function addVault(){ if (vaultItem.value){ vault.value.push(vaultItem.value); vaultItem.value=''; } }
async function refreshIntelligence(){ intel.value = ['C2 blocked: c2.evil.com', 'New signature RAT.XYZ']; }
const refreshIntel = refreshIntelligence;
</script>