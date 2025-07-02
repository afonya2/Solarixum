<script setup lang="ts">

</script>

<template>
  <div class="bg-slate-900 min-h-screen text-white px-6 py-12">
    <div class="max-w-3xl mx-auto">
      <h1 class="text-4xl font-bold mb-6">Terms of Service & Privacy Policy</h1>

      <section>
        <h2>1. Introduction</h2>
        <p>This chat application allows users to register, log in, and communicate securely with others. By using the app, you agree to these terms and our privacy policy.</p>
      </section>

      <section>
        <h2>2. Usage Limits</h2>
        <p>To ensure fair usage, we impose a limit of <strong>10,000 requests per hour</strong> per ip address. Abuse of this limit may result in temporary suspension.</p>
      </section>

      <section>
        <h2>3. End-to-End Encryption</h2>
        <p>Messages are <strong>truly end-to-end encrypted</strong>. However, please note that the system has <strong>not been audited or verified by a security expert</strong>. Use at your own discretion.</p>
      </section>

      <section>
        <h2>4. Data Collection</h2>
        <p>We collect and store the following data to operate the platform:</p>
        <ul>
          <li>Your username</li>
          <li>Your bio</li>
          <li>Your IP address</li>
          <li>The names of the rooms/universes you create</li>
          <li>Your profile picture (pfp)</li>
          <li>Your chat messages in an encrypted form</li>
          <li>Your public key</li>
          <li>Your private key in an ecrypted form. Only for you to be able to recover your account.</li>
          <li>Your password in a hashed form.</li>
        </ul>
      </section>

      <section>
        <h2>5. Data Sharing</h2>
        <p>We <strong>do not sell your data</strong> to third parties. Your data is only used to support the functionality of the app.</p>
      </section>

      <section>
        <h2>6. Analytics</h2>
        <p>We use <strong>Cloudflare Analytics</strong> to understand traffic patterns and improve the service. This data is anonymous and used solely for analytics purposes.</p>
      </section>

      <section>
        <h2>7. Contact</h2>
        <p>If you have any questions about these terms or your data, please check the source code <a href="https://github.com/afonya2/Solarixum">here</a></p>
      </section>
    </div>
  </div>
</template>

<style scoped>
section {
    margin-bottom: 2rem;
}
ul {
    list-style-type: disc;
    padding-left: 1.5rem;
}
a {
    color: rgb(50, 100, 200);
    text-decoration: underline;
}
</style>