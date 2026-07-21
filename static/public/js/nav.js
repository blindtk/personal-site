// Ficheiro estático servido tal-e-qual (fora do pipeline do Astro/Vite): faz
// parte de todas as páginas, por isso fica em /js/ em vez de hoisted num
// componente — evita ser recombinado com script específico de cada página
// num único bloco inline (era isso que fazia script-src crescer por página).
const toggle = document.querySelector('.nav-toggle');
const links = document.getElementById('nav-links');
const label = toggle?.querySelector('.nav-toggle-label');
const icon = toggle?.querySelector('.nav-toggle-icon');
toggle?.addEventListener('click', () => {
  const open = links?.classList.toggle('open');
  toggle.setAttribute('aria-expanded', String(Boolean(open)));
  if (label) label.textContent = open ? toggle.dataset.labelClose : toggle.dataset.labelOpen;
  if (icon) icon.textContent = open ? '×' : '≡';
});

// Fecha o dropdown "Segurança" ao clicar fora dele (o <details> nativo
// só fecha ao clicar de novo no <summary>).
document.querySelectorAll('.nav-security details').forEach((d) => {
  document.addEventListener('click', (e) => {
    if (d.open && !d.contains(e.target)) d.open = false;
  });
});
