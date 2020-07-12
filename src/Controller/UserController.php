<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class UserController extends AbstractController
{
    /**
     * @Route("/", name="api_home")
     * @return JsonResponse
     */
    public function home()
    {
        return $this->json([
            'result' => true
        ]);
    }

    /**
     * @Route("/register", name="api_register", methods={"POST"})
     * @param EntityManagerInterface $em
     * @param UserPasswordEncoderInterface $passwordEncoder
     * @param Request $request
     * @return JsonResponse
     */
    public function register(EntityManagerInterface $em, UserPasswordEncoderInterface $passwordEncoder, Request $request): JsonResponse
    {
        $user = new User();

        $email = $request->request->get("email");
        $password = $request->request->get("password");
        $password_confirmation = $request->request->get("password_confirmation");

        $errors = [];
        if ($password !== $password_confirmation) {
            $errors[] = "Password does not match the password confirmation";
        }

        if (strlen($password) < 6) {
            $errors[] = "Password should be at least 6 characters";
        }

        if (!$errors) {
            $encoderPassword = $passwordEncoder->encodePassword($user, $password);
            $user->setEmail($email);
            $user->setPassword($encoderPassword);

            try {
                $em->persist($user);
                $em->flush();

                return $this->json([
                    'user' => $user
                ]);
            }
            catch (UniqueConstraintViolationException $e) {
                $errors[] = "The email provider already has an account!";
            }
            catch (\Exception $e) {
                $errors[] = "Unable to save new user at this time.";
            }
        }

        return $this->json([
            'errors' => $errors
        ], 400);
    }

    /**
     * @Route("/login", name="api_login", methods={"POST"})
     * @param AuthenticationUtils $authenticationUtils
     * @return Response
     */
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    /**
     * @Route("/profile", name="api_profile")
     * @IsGranted("ROLE_USER")
     * @return JsonResponse
     */
    public function profile()
    {
        return $this->json([
           'user' => $this->getUser()
        ],
            200,
        [],
         [
                'groups' => ['api']
         ]
        );
    }

}
