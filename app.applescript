-- Auditar Permissões.app: pergunta o que remover e abre o relatório.
on run
	set py to "/usr/bin/python3 -I " & quoted form of (POSIX path of (path to resource "audit.py"))
	try
		set candidatos to paragraphs of (do shell script py & " --candidatos")
	on error msg
		if msg contains "Sem acesso" then
			display dialog "Este app precisa de Acesso Total ao Disco para ler as permissões do Mac." & return & return & "Nos Ajustes que vou abrir: clique em +, escolha \"Auditar Permissões\" em Aplicativos, ligue a chave e abra o app de novo." buttons {"Abrir Ajustes"} default button 1 with title "Auditar Permissões" with icon caution
			do shell script "open 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'"
		else
			display dialog msg buttons {"OK"} default button 1 with title "Auditar Permissões" with icon stop
		end if
		return
	end try

	if candidatos is not {} then
		set escolha to choose from list candidatos with title "Auditar Permissões" with prompt "Permissões novas ou religadas desde a última vez." & return & "Marque as que quer REMOVER (as outras ficam ligadas):" OK button name "Remover marcadas" cancel button name "Decidir depois" with multiple selections allowed and empty selection allowed
		if escolha is not false then
			set args to ""
			repeat with x in escolha
				set args to args & " " & quoted form of (x as text)
			end repeat
			do shell script py & " --decidir" & args
		end if
	end if

	set relatorio to do shell script py & " --relatorio"
	do shell script "open " & quoted form of relatorio
end run
