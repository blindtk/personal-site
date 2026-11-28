// Animação do diagrama de "O teu pedido, etapa a etapa" (RequestPath.astro).
// Importado de forma lazy (import()) e só em desktop, sem reduced-motion e
// quando a secção se aproxima do ecrã: quem não chega lá não descarrega o
// GSAP. Usa só o gsap-core (sem CSSPlugin): tudo o que anima são atributos
// SVG (stroke-dashoffset, cx/cy), que não passam pela CSP de estilos.
//
// Não há nada em ciclo: cada mudança de etapa dispara tweens curtos (≤ 0,6 s)
// e pára. Fora do ecrã ou com a aba escondida não corre nada (o ticker do
// GSAP usa requestAnimationFrame, que o browser suspende).
import { gsap } from 'gsap/gsap-core';

export interface PathAnimation {
  go(index: number): void;
}

const DRAW = { duration: 0.6, ease: 'power3.out' }; // ease-out forte, como as regras de movimento pedem
const UNDRAW = { duration: 0.2, ease: 'power2.out' };

export function mountPathAnimation(svg: SVGSVGElement): PathAnimation {
  const beams = [...svg.querySelectorAll<SVGGeometryElement>('[data-beam]')].sort(
    (a, b) => Number(a.dataset.beam) - Number(b.dataset.beam),
  );
  const nodes = [...svg.querySelectorAll<SVGElement>('[data-lit-at]')];
  const packet = svg.querySelector<SVGCircleElement>('[data-packet]');
  const lengths = beams.map((b) => b.getTotalLength());

  // Estado inicial: nenhuma etapa percorrida. Sem este passo (GSAP que não
  // carregou, reduced-motion), o CSS mostra o diagrama completo.
  beams.forEach((b, i) => {
    b.setAttribute('stroke-dasharray', `${lengths[i]} ${lengths[i]}`);
    b.setAttribute('stroke-dashoffset', String(lengths[i]));
  });
  svg.classList.add('is-animated');

  let current = -1;
  const probe = { t: 0 };

  function light(k: number) {
    for (const n of nodes) n.classList.toggle('lit', Number(n.dataset.litAt) <= k);
  }

  function travel(k: number) {
    const beam = beams[k];
    if (!packet || !beam || beam.dataset.packet === 'none') return;
    gsap.killTweensOf(probe);
    probe.t = 0;
    gsap.to(probe, {
      t: 1,
      ...DRAW,
      onStart: () => packet.classList.add('on'),
      onUpdate: () => {
        const p = beam.getPointAtLength(probe.t * lengths[k]);
        packet.setAttribute('cx', p.x.toFixed(1));
        packet.setAttribute('cy', p.y.toFixed(1));
      },
      onComplete: () => packet.classList.remove('on'),
    });
  }

  return {
    go(k: number) {
      if (k === current) return;
      beams.forEach((b, i) => {
        gsap.killTweensOf(b);
        const drawn = i <= k;
        if (i === k && k > current) {
          gsap.fromTo(b, { attr: { 'stroke-dashoffset': lengths[i] } }, { attr: { 'stroke-dashoffset': 0 }, ...DRAW });
        } else if (!drawn && i <= current) {
          gsap.to(b, { attr: { 'stroke-dashoffset': lengths[i] }, ...UNDRAW });
        } else {
          gsap.set(b, { attr: { 'stroke-dashoffset': drawn ? 0 : lengths[i] } });
        }
      });
      light(k);
      if (k > current) travel(k);
      current = k;
    },
  };
}
