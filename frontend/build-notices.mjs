import fs from 'node:fs';
import path from 'node:path';
export function dependencyNotices() {return {name:'packetpilot-dependency-notices',generateBundle(_,bundle) {
  const packages=new Map();
  for(const chunk of Object.values(bundle))if(chunk.type==='chunk')for(const [id,module]of Object.entries(chunk.modules)) {
    if(!module.renderedLength||!id.includes('/node_modules/'))continue;
    const normalized=id.replaceAll('\\','/').split('/node_modules/');const parts=normalized.at(-1).split('/');
    const name=parts[0].startsWith('@')?parts.slice(0,2).join('/'):parts[0];
    const root=normalized.slice(0,-1).join('/node_modules/')+'/node_modules/'+name;
    if(packages.has(name)||!fs.existsSync(path.join(root,'package.json')))continue;
    const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
    const notices=fs.readdirSync(root).filter(n=>/^(licen[sc]e|notice|copying)(\.|$)/i.test(n)&&fs.statSync(path.join(root,n)).isFile());
    let text=notices.map(n=>fs.readFileSync(path.join(root,n),'utf8')).join('\n\n');
    if(name==='victory-vendor') {
      const vendored=path.join(root,'lib-vendor');
      text=fs.readdirSync(vendored).flatMap(folder=>{const file=path.join(vendored,folder,'LICENSE');return fs.existsSync(file)?[folder+'\n'+fs.readFileSync(file,'utf8')]:[];}).join('\n\n');
      if(!text)throw new Error('Victory vendored license files are missing.');
    }
    if(!text){
      if(pkg.license!=='MIT')throw new Error('Review missing non-MIT package notice: '+name);
      // A few published npm archives omit a separate license file. Preserve
      // their actual SPDX/repository/author metadata and the MIT grant; never
      // manufacture a copyright holder or pretend a source notice was found.
      const grant=fs.readFileSync(path.resolve('node_modules/react/LICENSE'),'utf8').split('Permission is hereby granted')[1];
      text=`Installed npm archive declares MIT but supplies no separate license file.\nRepository: ${pkg.repository?.url||pkg.repository||pkg.homepage||'not supplied'}\nAuthor: ${typeof pkg.author==='string'?pkg.author:pkg.author?.name||'not supplied'}\n\nMIT License\nPermission is hereby granted${grant}`;
    }
    packages.set(name,{name,version:pkg.version,license:pkg.license,notice_source:name==='victory-vendor'?'npm archive lib-vendor LICENSE files':notices.length?'npm archive':'archive SPDX metadata and MIT grant',text});
  }
  const used=[...packages.values()].sort((a,b)=>a.name.localeCompare(b.name));
  const copied=fs.readFileSync(path.resolve('COPIED_COMPONENT_NOTICES.txt'),'utf8');
  this.emitFile({type:'asset',fileName:'THIRD_PARTY_NOTICES.txt',source:used.map(p=>`${p.name} ${p.version} (${p.license})\n${p.text}`).join('\n\n========================\n\n')+'\n\nCOPIED COMPONENT ADAPTATIONS\n\n'+copied});
  this.emitFile({type:'asset',fileName:'BUILD.json',source:JSON.stringify({interface:'react-premium-workspace-1.1',built_at:new Date().toISOString(),node:process.version,dependencies:used.map(({text,...p})=>p),copied_component_notices:'THIRD_PARTY_NOTICES.txt'},null,2)+'\n'});
}};}
