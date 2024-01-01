#### Segundo projeto  -SIO

## Index

1. Introdução

2. ASVS

- 2.1.2

- 2.1.7

- 2.1.8

- 2.2.1

- 2.2.3

- 3.2.3

- 3.3.2

- 4.2.2

- 4.3.1

- 5.3.6

- 8.3.2

- 11.1.4

- 13.2.3

- 14.2.3

3. Conclusão

## 1. Introdução

De modo a dar continuidade ao trabalho realizado no primeiro projeto analisámos os principais problemas de segurança deste com auxilio do documento excel disponibilizado pelo os docentes da UC.<br>
Com esta analise chegamos aos principais dez problemas do site desnvolvido.<br>
No desenvolvimento deste projeto procuramos resoler os problemas identificados para tornar o nosso site o mais seguro possível tanto para um normal utilizador como para a empresa que usar os nossos serviços.

## 2. ASVS

Entre as vunerabilidades que o nosso site apresenta estas são as dez que considerámos mais urgentes de serem corrigidas devido ao nivel de compretimento em que podem deixar um utilizador ou entidade responsavel site.

## ASVS - 2.1.2



### Demonstração



## Correção


## ASVS - 2.1.7


## Demonstração


## Correção


## Demonstração


## Correção

## ASVS - 2.2.1

A ASVS - 2.2.1 consiste em criar uma verificação para o número de caracteres possiveis de serem aceites em uma password de um utilizador. De modo a uniformizar e a garantir a segurança dos utilizadores as passwords permitidas têm de ter entre 12 a 128 caracteres.
Falta dizer porque é que escolhemos isto!!!
## Demonstração
De modo a regular o número máximo de caracteres usados em passwords de utilizadores foi implementado uma verificação no ato de registo dos utilizadores.

```python
if len(user.password) < 12:
                flash('Password must have at least 12 characters.')
                return redirect(url_for('profile.edit_profile'))
            elif len(user.password) > 128:
                flash('Password must have less than 128 characters.')
                return redirect(url_for('profile.edit_profile'))
```


## ASVS - 2.2.3

A ASVS - 2.2.3 consiste em enviar informação de forma segura aos utilizadores sempre que estes alterem informações no seu regiisto.
A forma que escolhemos para enviar esta informação foi via email, assim o utilizador pode verificar que alterações foram efetuadas e caso não tenho sido o mesmo a faze-las entarar em contacto com os donos do site.
Falta dizer porque é que escolhemos isto!!!

## Demonstração

A implementação foi feita de modo a que os utilizadores recebam um e-mail personalizado caso alterem a sua password ou qualquer outra informação no seu perfil.<br>
Com istos estes estão mais seguros pois em caso de alteração indevida de informações do legitimo utilizador este poderá entrar em contacto com os representantes da empresa para resolver rapidamente o seu problema.

```python
flash('Profile updated successfully!')

            msg = Message("Profile updated")
            msg.recipients= [current_email]
            msg.body = """Dear {username},

            We hope this message finds you well. We wanted to inform you that your profile on Deti@Merch has been successfully updated. Your information is now current, ensuring a seamless and personalized experience on our site.

            If you did not make these changes or have any concerns about your account security, please reach out to us at "detimerch@gmail.com". We take the security of your account seriously and will investigate any unauthorized changes promptly.

            Thank you for choosing Deti@Merch. We appreciate your trust in us, and we're committed to providing you with the best shopping experience.

            Best regards,
            Deti@Merch Security Team
            """.format(username=user.username)

            mail.send(msg)
            db.session.commit()
            return redirect(url_for('profile.profile'))
```
```python
flash('Password changed successfully!')
                user.password = generate_password_hash(new_password, method='sha256')

                msg = Message("Password updated")
                msg.recipients= [current_email]
                msg.body = """Dear {username},

                We hope this message finds you well. We wanted to inform you that your password on Deti@Merch has been successfully updated. Your information is now current, ensuring a seamless and personalized experience on our site.

                If you did not make these changes or have any concerns about your account security, please reach out to us at "detimerch@gmail.com". We take the security of your account seriously and will investigate any unauthorized changes promptly.

                Thank you for choosing Deti@Merch. We appreciate your trust in us, and we're committed to providing you with the best shopping experience.

                Best regards,
                Deti@Merch Security Team
                """.format(username=user.username)

                mail.send(msg)
                db.session.commit()     
                return redirect(url_for('profile.edit_profile'))

```

## ASVS - 3.2.3

A ASVS - 3.2.3 

## Demonstração


## Correção


## ASVS - 3.3.2

A ASVS - 3.3.2 garante que um utilizador que se tenha logado com sucesso o tenha de se autenticar novamente passados 30 dias da autenticação anterior.
Falta dizer porque é que escolhemos isto!!!

## Demonstração



## Correção




## Demonstração



## Correção



## ASVS - 4.3.1

A ASVS - 4.3.1 garante que para ter acesso aos à conta de um determinado utilizador este tenha de passar por um processo de auntenticação multifatorial.

## Demonstração



## ASVS - 5.3.6

REIS

## ASVS - 11.1.4



## ASVS - 13.2.3



## ASVS - 14.2.3

REIS

## 3. Conclusão



