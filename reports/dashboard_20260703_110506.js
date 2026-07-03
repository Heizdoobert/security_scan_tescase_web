function toggleRow(id){
  var row=document.getElementById(id);
  var detail=document.querySelector('[data-parent="'+id+'"]');
  if(!detail) return;
  row.classList.toggle('expanded');
  detail.classList.toggle('expanded');
}

function applyFilters(){
  var q=document.getElementById('search').value.toLowerCase();
  var m=document.getElementById('moduleFilter').value;
  var v=document.getElementById('severityFilter').value;
  var checks={};
  document.querySelectorAll('.sf').forEach(function(cb){checks[cb.value]=cb.checked});
  var rows=document.querySelectorAll('#results-table tbody .result-row');
  var visible=0;
  rows.forEach(function(r){
    var status=r.classList.contains('pass')?'pass':r.classList.contains('fail')?'fail':r.classList.contains('warn')?'warn':r.classList.contains('error')?'error':'';
    var show=true;
    if(!checks[status]) show=false;
    if(q && !r.textContent.toLowerCase().includes(q)) show=false;
    if(m && r.querySelector('.module-tag') && r.querySelector('.module-tag').textContent!==m) show=false;
    if(v){
      var sevEl=r.querySelector('[class^="sev-"]');
      if(sevEl && sevEl.textContent.toLowerCase()!==v) show=false;
    }
    r.style.display=show?'':'none';
    var detail=document.querySelector('[data-parent="'+r.id+'"]');
    if(detail) detail.style.display=show && detail.classList.contains('expanded')?'':'none';
    if(show) visible++;
  });
  document.getElementById('noMatch').classList.toggle('hidden',visible>0);
}

// Sort by column
document.querySelectorAll('#results-table th.sortable').forEach(function(th){
  th.addEventListener('click',function(){
    var col=th.getAttribute('data-col');
    if(!col) return;
    var tbody=document.querySelector('#results-table tbody');
    var all=Array.from(tbody.querySelectorAll('tr'));
    var rows=all.filter(function(r){return r.classList.contains('result-row')});
    var dir=th._dir==='asc'?'desc':'asc';
    th._dir=dir;
    document.querySelectorAll('#results-table th .arrow').forEach(function(a){a.textContent=''});
    var arrow=document.createElement('span');
    arrow.className='arrow';
    arrow.textContent=dir==='asc'?' \u25b2':' \u25bc';
    th.appendChild(arrow);
    rows.sort(function(a,b){
      var getVal=function(r){
        if(col==='result') return r.querySelector('.badge')?r.querySelector('.badge').textContent.trim().toLowerCase():'';
        if(col==='testId') return (r.querySelector('.col-testId')||r.cells[2]).textContent.trim().toLowerCase();
        if(col==='module') return r.querySelector('.module-tag')?r.querySelector('.module-tag').textContent.trim().toLowerCase():'';
        if(col==='severity'){var se=r.querySelector('[class^="sev-"]');return se?se.textContent.trim().toLowerCase():'';}
        return '';
      };
      var va=getVal(a),vb=getVal(b);
      if(va<vb) return dir==='asc'?-1:1;
      if(va>vb) return dir==='asc'?1:-1;
      return 0;
    });
    rows.forEach(function(r){
      tbody.appendChild(r);
      var detail=document.querySelector('[data-parent="'+r.id+'"]');
      if(detail) tbody.appendChild(detail);
    });
  });
});
