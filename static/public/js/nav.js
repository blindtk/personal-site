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
// só fecha ao clicar de novo no <summary>) ou com Escape a partir de
// dentro dele — o <details> nativo também não trata Escape sozinho, e sem
// isto um utilizador de teclado só o fecha voltando a tab até ao summary.
document.querySelectorAll('.nav-security details').forEach((d) => {
  document.addEventListener('click', (e) => {
    if (d.open && !d.contains(e.target)) d.open = false;
  });
  d.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && d.open) {
      d.open = false;
      d.querySelector('summary')?.focus();
    }
  });
});

// Scroll horizontal por setas nos contentores .table-scroll (CSP Lint,
// Violações CSP, Vigia CT, Cloudflare, cadeia de entrega/resumo de
// cabeçalhos de email): têm tabindex="0" para serem alcançáveis por
// tab, mas as setas do teclado não rolam overflow:auto por omissão em
// todos os browsers — sem isto, ficam focáveis mas inúteis.
document.querySelectorAll('.table-scroll[tabindex]').forEach((el) => {
  el.addEventListener('keydown', (e) => {
    const step = 80;
    if (e.key === 'ArrowRight') { el.scrollLeft += step; e.preventDefault(); }
    else if (e.key === 'ArrowLeft') { el.scrollLeft -= step; e.preventDefault(); }
    else if (e.key === 'Home') { el.scrollLeft = 0; e.preventDefault(); }
    else if (e.key === 'End') { el.scrollLeft = el.scrollWidth; e.preventDefault(); }
  });
});
