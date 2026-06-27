/* Trust Score leaderboard — riskiest users first, with click-through to a
   full breakdown in the detail drawer. */

const Trust = (() => {
  let scores = [];

  async function init(onCardClick) {
    scores = await API.trustScores('ascending'); // riskiest first
    render(onCardClick);
    return scores;
  }

  function render(onCardClick) {
    const list = document.getElementById('trust-list');
    list.innerHTML = '';

    scores.forEach((s) => {
      const color = Util.RISK_COLOR[s.risk_level] || '#7C8798';

      const card = Util.el('div', { class: 'trust-card', onclick: () => onCardClick && onCardClick(s) }, [
        Util.el('div', { class: 'trust-card-top' }, [
          Util.el('span', { class: 'trust-user' }, [s.user]),
          Util.el('span', { class: 'trust-score-val', style: `color:${color}` }, [s.trust_score.toFixed(1)]),
        ]),
        Util.el('div', { class: 'trust-bar-track' }, [
          Util.el('div', {
            class: 'trust-bar-fill',
            style: `width:${s.trust_score}%; background:${color}`,
          }),
        ]),
        Util.el('div', { class: 'trust-card-meta' }, [
          Util.el('span', { class: 'risk-badge', style: `background:${color}22; color:${color}` }, [s.risk_level]),
          Util.el('span', {}, [`${s.incident_count} incident${s.incident_count === 1 ? '' : 's'}`]),
        ]),
      ]);

      list.appendChild(card);
    });
  }

  return { init, get: () => scores };
})();
